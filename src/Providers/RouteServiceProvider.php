<?php

declare(strict_types=1);

namespace Nvl\Auth\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Http\Middleware\ApplyAuthSecurityHeaders;
use Nvl\Auth\Http\Middleware\AuthenticateAuthGuard;
use Nvl\Auth\Http\Middleware\EnsureAuthFeatureAvailable;
use Nvl\Auth\Http\Middleware\RenderAuthExceptions;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;
use Nvl\Auth\ValueObjects\FeatureDefinition;
use Nvl\Support\Globals\GlobalNames;

/**
 * Registers only effective, explicitly enabled package route families.
 */
final class RouteServiceProvider extends ServiceProvider
{
    /**
     * Register stable aliases, throttles, and effective routes.
     */
    public function boot(
        Router $router,
        AuthConfiguration $configuration,
        FeatureManifest $manifest,
        FeatureGate $features,
    ): void {
        if (! $configuration->enabled()
            || ! $configuration->boolean('routes.enabled', false)) {
            return;
        }

        $surfaces = [];
        foreach (['public', 'account', 'management'] as $surface) {
            if (! $configuration->boolean("routes.{$surface}.enabled", false)) {
                continue;
            }
            foreach ($manifest->definitions() as $definition) {
                if (is_string($definition->routeFamilies[$surface] ?? null)
                    && $configuration->featureRoutesEnabled($definition->feature, $surface)
                    && $features->allows($definition->feature, FeatureOperation::Read)
                    && $this->dependenciesAvailable($definition, $surface, $features)) {
                    $surfaces[] = $surface;
                    break;
                }
            }
        }
        if ($surfaces === []) {
            return;
        }

        $names = $this->app->make(GlobalNames::class);
        foreach (['nvl-auth.feature' => ['nvl.auth.feature', EnsureAuthFeatureAvailable::class],
            'nvl-auth.guard' => ['nvl.auth.guard', AuthenticateAuthGuard::class]] as $legacy => [$canonical, $middleware]) {
            $exists = static fn (string $name): bool => array_key_exists($name, $router->getMiddleware());
            $install = static function (string $name) use ($router, $middleware): void {
                $router->aliasMiddleware($name, $middleware);
            };
            $names->reserve('auth', 'middleware', $canonical, $exists, $install);
            $names->register('auth', 'middleware', $legacy, $canonical, $exists, $install);
        }
        $this->registerRateLimiters($surfaces);
        if ($this->app->routesAreCached()) {
            return;
        }

        $prefix = trim($configuration->string('routes.prefix', 'nvl/api/v1/auth'), '/');
        $this->app->make(GlobalNames::class)->loadRoutes('auth', $router, function () use ($prefix, $configuration, $features, $manifest): void {
            Route::prefix($prefix)
                ->name('nvl.auth.')
                ->group(function () use ($configuration, $features, $manifest): void {
                    foreach (['public', 'account', 'management'] as $surface) {
                        $this->mapSurface($surface, $configuration, $manifest, $features);
                    }
                });
        });
    }

    /**
     * Register package rate-limit policies.
     *
     * @param  list<string>  $surfaces
     */
    private function registerRateLimiters(array $surfaces): void
    {
        $names = $this->app->make(GlobalNames::class);
        foreach ($surfaces as $surface) {
            $maximum = ['public' => 10, 'account' => 30, 'management' => 60][$surface];
            $limiter = static fn (Request $request): Limit => Limit::perMinute($maximum)->by(self::requestKey($request));
            $exists = static fn (string $name): bool => RateLimiter::limiter($name) !== null;
            $install = static function (string $name) use ($limiter): void {
                RateLimiter::for($name, $limiter);
            };
            $names->reserve('auth', 'limiter', 'nvl.auth.'.$surface, $exists, $install);
            $names->register('auth', 'limiter', 'nvl-auth-'.$surface, 'nvl.auth.'.$surface, $exists, $install);
        }
    }

    /**
     * Resolve a stable scalar rate-limit key.
     */
    private static function requestKey(Request $request): string
    {
        $identifier = $request->user()?->getAuthIdentifier();

        if (is_string($identifier) || is_int($identifier)) {
            return (string) $identifier;
        }

        return $request->ip() ?? 'unknown';
    }

    /**
     * Register every effective feature family for one surface.
     */
    private function mapSurface(
        string $surface,
        AuthConfiguration $configuration,
        FeatureManifest $manifest,
        FeatureGate $features,
    ): void {
        if (! $configuration->boolean("routes.{$surface}.enabled", false)) {
            return;
        }

        foreach ($manifest->definitions() as $definition) {
            $family = $definition->routeFamilies[$surface] ?? null;

            if (! is_string($family)
                || ! $configuration->featureRoutesEnabled($definition->feature, $surface)
                || ! $features->allows($definition->feature, FeatureOperation::Read)
                || ! $this->dependenciesAvailable($definition, $surface, $features)) {
                continue;
            }

            $this->mapFamily($surface, $family, $definition, $configuration);
        }
    }

    /**
     * Load one route family behind feature and dependency middleware.
     */
    private function mapFamily(
        string $surface,
        string $family,
        FeatureDefinition $definition,
        AuthConfiguration $configuration,
    ): void {
        $path = dirname(__DIR__, 2)."/routes/{$surface}/{$family}.php";

        if (! is_file($path)) {
            return;
        }

        $featureMiddleware = [
            "nvl.auth.feature:{$definition->feature->value},read",
            ...array_map(
                static fn ($dependency): string => "nvl.auth.feature:{$dependency->value},read",
                $definition->dependenciesForSurface($surface),
            ),
        ];
        Route::name("{$surface}.")
            ->middleware([
                ApplyAuthSecurityHeaders::class,
                RenderAuthExceptions::class,
                ...$featureMiddleware,
                ...$this->middleware($configuration->get('routes.middleware', ['api'])),
                ...$this->middleware($configuration->get("routes.{$surface}.middleware", [])),
            ])
            ->group($path);
    }

    /**
     * Determine whether every route-surface dependency is effective.
     */
    private function dependenciesAvailable(
        FeatureDefinition $definition,
        string $surface,
        FeatureGate $features,
    ): bool {
        foreach ($definition->dependenciesForSurface($surface) as $dependency) {
            if (! $features->allows($dependency, FeatureOperation::Read)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Normalize a middleware configuration list.
     *
     * @return list<string>
     */
    private function middleware(mixed $configured): array
    {
        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration('Auth route middleware configuration must be an array.');
        }

        $middleware = [];

        foreach ($configured as $entry) {
            if (! is_string($entry) || trim($entry) === '') {
                throw AuthException::invalidConfiguration(
                    'Auth route middleware configuration must contain non-empty strings.',
                );
            }

            $middleware[] = trim($entry);
        }

        return $middleware;
    }
}
