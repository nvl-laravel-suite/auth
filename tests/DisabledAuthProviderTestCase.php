<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Tests\Fixtures\HostPersonalAccessToken;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Orchestra\Testbench\TestCase as Orchestra;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Boots a globally disabled Auth provider over host-owned integrations.
 */
abstract class DisabledAuthProviderTestCase extends Orchestra
{
    /**
     * Register Auth without manually registering its Data dependency.
     *
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            PermissionServiceProvider::class,
            SanctumServiceProvider::class,
            AuthServiceProvider::class,
        ];
    }

    /**
     * Configure host-owned Auth, Permission, and Sanctum state before package boot.
     */
    protected function defineEnvironment($app): void
    {
        Sanctum::usePersonalAccessTokenModel(HostPersonalAccessToken::class);
        $app['config']->set('nvl-auth.enabled', false);
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.defaults.passwords', 'users');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => TestUser::class]);
        $app['config']->set('auth.passwords.users', [
            'provider' => 'users',
            'table' => 'host_password_reset_tokens',
            'expire' => 60,
            'throttle' => 0,
        ]);
        $app['config']->set('permission.models.role', Role::class);
        $app['config']->set('permission.models.permission', Permission::class);
        $app['config']->set('permission.table_names', [
            'roles' => 'host_roles',
            'permissions' => 'host_permissions',
            'model_has_permissions' => 'host_model_has_permissions',
            'model_has_roles' => 'host_model_has_roles',
            'role_has_permissions' => 'host_role_has_permissions',
        ]);
    }

    /**
     * Restore Sanctum's process-wide default after provider verification.
     */
    protected function tearDown(): void
    {
        Sanctum::usePersonalAccessTokenModel(PersonalAccessToken::class);

        parent::tearDown();
    }
}
