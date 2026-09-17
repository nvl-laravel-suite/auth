<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Contracts\Foundation\MaintenanceMode;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Http\Middleware\ApplyAuthSecurityHeaders;
use Nvl\Auth\Http\Middleware\RenderAuthExceptions;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;
use Nvl\Auth\Tests\Fixtures\AllowAllSystemMutationAccess;
use Nvl\Auth\Tests\Fixtures\AuthTestMaintenanceMode;
use Nvl\Auth\Tests\Fixtures\AuthTestPlatformAccess;
use Nvl\Auth\Tests\Fixtures\AuthTestTenantDirectory;
use Nvl\Auth\Tests\Fixtures\AuthTestTenantHttpResolver;
use Nvl\Auth\Tests\Fixtures\TestSubjectResolver;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Data\Providers\DataServiceProvider;
use Nvl\Tenancy\Contracts\PlatformAccess;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Providers\TenancyServiceProvider;
use Nvl\Tenancy\Services\DenyTenantMembershipAccess;
use Nvl\Tenancy\Services\TenantAdoptionCoordinator;
use Nvl\Tenancy\ValueObjects\PlatformOperation;
use Orchestra\Testbench\TestCase as Orchestra;
use ReflectionClass;
use RuntimeException;
use Spatie\LaravelData\LaravelDataServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/** Boots the complete Auth tenant integration without an outer transaction. */
abstract class TenancyTestCase extends Orchestra
{
    use DatabaseMigrations;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [
            PermissionServiceProvider::class,
            SanctumServiceProvider::class,
            LaravelDataServiceProvider::class,
            DataServiceProvider::class,
            TenancyServiceProvider::class,
            AuthServiceProvider::class,
        ];
    }

    /** Configure an isolated opt-in tenant host. */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.name', 'NVL Auth Tenant Test');
        $app['config']->set('app.url', 'https://auth-package.test');
        $app['config']->set('app.key', 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=');
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.defaults.passwords', 'users');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => TestUser::class]);
        $app['config']->set('auth.passwords.users', ['provider' => 'users', 'table' => 'password_reset_tokens', 'expire' => 60, 'throttle' => 0]);
        $app['config']->set('nvl-auth.features.principal_management.models.user', TestUser::class);
        $app['config']->set('nvl-auth.migrations.install_all', true);
        foreach (['memberships', 'invitations', 'rbac', 'audit', 'api_tokens'] as $feature) {
            $app['config']->set("nvl-auth.features.{$feature}.enabled", true);
        }
        $app['config']->set('nvl-auth.features.api_tokens.settings.abilities', ['profile:read']);
        $app['config']->set('nvl-auth.routes.enabled', true);
        $app['config']->set('nvl-auth.routes.middleware', ['api']);
        $app['config']->set('nvl-auth.routes.account.enabled', true);
        $app['config']->set('nvl-auth.routes.management.enabled', true);
        $app['config']->set('nvl-auth.features.memberships.routes.account.enabled', true);
        $app['config']->set('nvl-auth.features.memberships.routes.management.enabled', true);
        $app['config']->set('tenancy.enabled', true);
        $app['config']->set('tenancy.access.membership', DenyTenantMembershipAccess::class);
        $app['config']->set('tenancy.access.platform', AuthTestPlatformAccess::class);
        $app['config']->set('tenancy.directory', ['driver' => 'host', 'adapter' => AuthTestTenantDirectory::class]);
        $app['config']->set('tenancy.resolvers.http', AuthTestTenantHttpResolver::class);
        $app['config']->set('nvl-auth.tenancy.migrations.enabled', true);
        $app->singleton(TenantDirectory::class, AuthTestTenantDirectory::class);
        $app->singleton(PlatformAccess::class, AuthTestPlatformAccess::class);
        $app->singleton(MaintenanceMode::class, AuthTestMaintenanceMode::class);
        $app->singleton(TenantHttpResolver::class, AuthTestTenantHttpResolver::class);
    }

    /** Bind host contracts and activate the real empty Auth adoption. */
    protected function setUp(): void
    {
        parent::setUp();
        $this->app->singleton(AuthManagementAccess::class, AllowAllManagementAccess::class);
        $this->app->singleton(AuthSubjectResolver::class, TestSubjectResolver::class);
        $this->app->singleton(SystemMutationAccess::class, AllowAllSystemMutationAccess::class);
        $this->activateEmptyAuthTenancy();
        if ($this->deactivateMaintenanceAfterSetup()) {
            $this->app->make(MaintenanceMode::class)->deactivate();
        }
    }

    /** Register only the tenancy route surfaces exercised by this fixture. */
    protected function defineRoutes($router): void
    {
        Route::prefix('api/v1/auth')->name('nvl.auth.')->group(function (): void {
            Route::name('account.')->middleware(['api', 'auth', ApplyAuthSecurityHeaders::class, RenderAuthExceptions::class])
                ->group(dirname(__DIR__).'/routes/account/memberships.php');
            Route::name('management.')->middleware(['api', 'auth', ApplyAuthSecurityHeaders::class, RenderAuthExceptions::class])
                ->group(dirname(__DIR__).'/routes/management/memberships.php');
        });
    }

    /** Load the opt-in foundation core after Testbench refreshes storage. */
    protected function defineDatabaseMigrationsAfterDatabaseRefreshed(): void
    {
        $provider = new ReflectionClass(TenancyServiceProvider::class);
        $this->loadMigrationsFrom(dirname((string) $provider->getFileName()).'/../../database/migrations/tenancy');
    }

    /** Activate empty Auth storage through the production coordinator. */
    protected function activateEmptyAuthTenancy(): void
    {
        $coordinator = app(TenantAdoptionCoordinator::class);
        $operation = new PlatformOperation('auth-test.adoption', 'system', 'fixture');
        $plan = $coordinator->prepare(['auth'], [], $operation);
        $attempts = 0;
        while (! $coordinator->backfill($plan, 100, $operation)) {
            if (++$attempts > 100) {
                throw new RuntimeException('Auth test adoption failed to advance.');
            }
        }
        if (! $coordinator->verify($plan)->passed()) {
            throw new RuntimeException('Auth test adoption failed verification.');
        }
        $coordinator->activate($plan, $operation);
    }

    /** Allow explicit adoption tests to retain their maintenance lease. */
    protected function deactivateMaintenanceAfterSetup(): bool
    {
        return true;
    }

    /** Create one conventional fixture user. */
    protected function user(string $email = 'user@example.test'): TestUser
    {
        return TestUser::query()->create(['name' => 'Test User', 'email' => $email, 'password' => 'correct-password']);
    }
}
