<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Providers\RouteServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;

it('registers a route only when global surface and feature switches are enabled', function (): void {
    app()->instance('routes.cached', false);
    expect(Route::has('nvl.auth.public.login'))->toBeFalse();
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set('nvl-auth.features.authentication.routes.public.enabled', true);
    $provider = new RouteServiceProvider(app());
    $provider->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    Route::getRoutes()->refreshNameLookups();

    expect(Route::has('nvl.auth.public.login'))->toBeTrue();
});

it('fails stale registered routes closed after a feature is disabled', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set('nvl-auth.features.authentication.routes.public.enabled', true);
    $provider = new RouteServiceProvider(app());
    $provider->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    config()->set('nvl-auth.features.authentication.enabled', false);

    $response = $this->postJson('/api/v1/auth/login', [
        'identifier' => 'user@example.test',
        'password' => 'secret',
    ])->assertNotFound()->assertJson([
        'data' => null,
        'code' => 'feature_unavailable',
    ]);

    $response->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Pragma', 'no-cache')
        ->assertHeader('Referrer-Policy', 'no-referrer')
        ->assertHeader('X-Content-Type-Options', 'nosniff');
});

it('does not register browser authentication families without session dependencies', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set('nvl-auth.features.authentication.routes.public.enabled', true);
    config()->set('nvl-auth.features.sessions.enabled', false);
    $provider = new RouteServiceProvider(app());
    $provider->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    Route::getRoutes()->refreshNameLookups();

    expect(Route::has('nvl.auth.public.login'))->toBeFalse();
});

it('rejects stale model-bound routes before authentication or database binding', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.management.enabled', true);
    config()->set('nvl-auth.features.clients.enabled', true);
    config()->set('nvl-auth.features.clients.routes.management.enabled', true);
    $provider = new RouteServiceProvider(app());
    $provider->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    config()->set('nvl-auth.features.clients.enabled', false);
    DB::flushQueryLog();
    DB::enableQueryLog();

    $this->deleteJson('/api/v1/auth/clients/00000000-0000-0000-0000-000000000000')
        ->assertNotFound()
        ->assertJson(['data' => null, 'code' => 'feature_unavailable']);

    expect(DB::getQueryLog())->toBe([]);
    DB::disableQueryLog();
});

it('keeps the all-enabled route inventory identical to the canonical manifest', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);

    foreach (['public', 'account', 'management'] as $surface) {
        config()->set("nvl-auth.routes.{$surface}.enabled", true);
    }

    foreach (AuthFeature::cases() as $feature) {
        config()->set("nvl-auth.features.{$feature->value}.enabled", true);

        foreach (['public', 'account', 'management'] as $surface) {
            config()->set("nvl-auth.features.{$feature->value}.routes.{$surface}.enabled", true);
        }
    }

    $manifest = app(FeatureManifest::class);
    (new RouteServiceProvider(app()))->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        $manifest,
        app(FeatureGate::class),
    );
    Route::getRoutes()->refreshNameLookups();
    $expected = [];

    foreach ($manifest->definitions() as $definition) {
        foreach ($definition->routeNames as $surface => $names) {
            foreach ($names as $name) {
                $expected[] = "nvl.auth.{$surface}.{$name}";
            }
        }
    }

    $actual = array_values(array_filter(
        array_keys(Route::getRoutes()->getRoutesByName()),
        static fn (string $name): bool => str_starts_with($name, 'nvl.auth.'),
    ));
    sort($expected);
    sort($actual);

    expect($actual)->toBe($expected);
});
