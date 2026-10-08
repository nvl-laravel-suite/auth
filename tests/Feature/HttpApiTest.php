<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Timebox;
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

    $created = $this->postJson('/nvl/api/v1/auth/clients', [
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

    $this->getJson("/nvl/api/v1/auth/clients/{$clientId}")
        ->assertOk()
        ->assertJsonPath('data.metadata.owner', 'platform');
    $this->patchJson("/nvl/api/v1/auth/clients/{$clientId}/status", ['active' => false])
        ->assertOk()
        ->assertJsonPath('code', 'client_deactivated')
        ->assertHeader('Cache-Control', 'no-store, private');

    $audit = AuthAudit::query()->where('action', 'client.created')->sole();
    $this->getJson("/nvl/api/v1/auth/audits/{$audit->identifier()}")
        ->assertOk()
        ->assertJsonPath('data.metadata.surface', 'web');
});

it('timeboxes known and unknown account requests while keeping responses neutral', function (string $path, AuthFeature $feature, string $identifier): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set("nvl-auth.features.{$feature->value}.enabled", true);
    config()->set("nvl-auth.features.{$feature->value}.routes.public.enabled", true);
    Event::fake([AuthDeliveryRequested::class]);
    (new RouteServiceProvider(app()))->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    $user = $this->user();
    $timebox = Mockery::mock(Timebox::class);
    $timebox->shouldReceive('dontReturnEarly')->twice()->andReturnSelf();
    $timebox->shouldReceive('call')->twice()->withArgs(static fn (callable $callback, int $duration): bool => $duration === 200_000)
        ->andReturnUsing(static fn (callable $callback): mixed => $callback());
    app()->instance(Timebox::class, $timebox);

    $extra = $feature === AuthFeature::SecurityCodes ? ['purpose' => 'passwordless_login'] : [];
    $unknown = $this->postJson('/nvl/api/v1/auth/'.$path, [$identifier => 'unknown@example.test', ...$extra])
        ->assertAccepted();
    $known = $this->postJson('/nvl/api/v1/auth/'.$path, [$identifier => $user->email, ...$extra])
        ->assertAccepted();

    expect($known->json())->toBe($unknown->json());

    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
    Event::assertDispatched(
        AuthDeliveryRequested::class,
        static fn (AuthDeliveryRequested $event): bool => $event->request->feature === $feature,
    );
})->with([
    ['magic-links', AuthFeature::MagicLinks, 'recipient'],
    ['security-codes/authentication', AuthFeature::SecurityCodes, 'recipient'],
    ['password/forgot', AuthFeature::Password, 'identifier'],
]);

it('rejects oversized magic-link purposes identically for known and unknown accounts', function (int $length): void {
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
    $purpose = str_repeat('a', $length);
    $unknown = $this->postJson('/nvl/api/v1/auth/magic-links', [
        'recipient' => 'unknown@example.test',
        'purpose' => $purpose,
    ]);
    $known = $this->postJson('/nvl/api/v1/auth/magic-links', [
        'recipient' => $user->email,
        'purpose' => $purpose,
    ]);

    $unknown->assertUnprocessable()->assertJsonValidationErrors('purpose');
    $known->assertUnprocessable()->assertJsonValidationErrors('purpose');
    expect($known->json())->toBe($unknown->json());
    Event::assertNotDispatched(AuthDeliveryRequested::class);
})->with([121, 255]);
