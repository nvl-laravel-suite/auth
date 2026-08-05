<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Providers\RouteServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;

it('serves the authorized client and audit management lifecycle', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.management.enabled', true);
    config()->set('nvl-auth.features.clients.enabled', true);
    config()->set('nvl-auth.features.clients.routes.management.enabled', true);
    config()->set('nvl-auth.features.audit.routes.management.enabled', true);
    (new RouteServiceProvider(app()))->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    Route::getRoutes()->refreshNameLookups();
    $actor = $this->user('manager@example.test');
    $this->actingAs($actor, 'web');

    $created = $this->postJson('/api/v1/auth/clients', [
        'name' => 'Admin Portal',
        'surface' => 'web',
        'baseUrl' => 'https://admin.example.test',
        'returnPaths' => ['/dashboard'],
        'allowedOrigins' => ['https://admin.example.test'],
        'allowedFlows' => ['login'],
        'metadata' => ['owner' => 'platform'],
    ])->assertCreated()->assertJsonPath('code', 'client_created');
    $clientId = $created->json('data.id');

    expect($clientId)->toBeString();

    $this->getJson("/api/v1/auth/clients/{$clientId}")
        ->assertOk()
        ->assertJsonPath('data.metadata.owner', 'platform');
    $this->patchJson("/api/v1/auth/clients/{$clientId}/status", ['active' => false])
        ->assertOk()
        ->assertJsonPath('code', 'client_deactivated')
        ->assertHeader('Cache-Control', 'no-store, private');

    $audit = AuthAudit::query()->where('action', 'client.created')->sole();
    $this->getJson("/api/v1/auth/audits/{$audit->identifier()}")
        ->assertOk()
        ->assertJsonPath('data.metadata.surface', 'web');
});

it('keeps public magic-link account discovery neutral while binding known subjects', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set('nvl-auth.features.magic_links.enabled', true);
    config()->set('nvl-auth.features.magic_links.routes.public.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    (new RouteServiceProvider(app()))->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    $user = $this->user();

    $this->postJson('/api/v1/auth/magic-links', ['recipient' => 'unknown@example.test'])
        ->assertAccepted()
        ->assertJsonPath('code', 'magic_link_requested');
    $this->postJson('/api/v1/auth/magic-links', ['recipient' => $user->email])
        ->assertAccepted()
        ->assertJsonPath('code', 'magic_link_requested');

    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
    Event::assertDispatched(
        AuthDeliveryRequested::class,
        static fn (AuthDeliveryRequested $event): bool => $event->request->feature === AuthFeature::MagicLinks,
    );
});
