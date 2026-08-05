<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;
use Nvl\Auth\Tests\Fixtures\TestSubjectResolver;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Orchestra\Testbench\TestCase as Orchestra;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Boots NVL Auth with only its declared integration providers.
 */
abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    /**
     * Register package integration providers.
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
     * Configure the isolated host application.
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.name', 'NVL Auth Test');
        $app['config']->set('app.url', 'https://auth-package.test');
        $app['config']->set('app.key', 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=');
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.defaults.passwords', 'users');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => TestUser::class]);
        $app['config']->set('auth.passwords.users', ['provider' => 'users', 'table' => 'password_reset_tokens', 'expire' => 60, 'throttle' => 0]);
        $app['config']->set('nvl-auth.features.principal_management.models.user', TestUser::class);
        $app['config']->set('nvl-auth.routes.enabled', false);
        $app['config']->set('nvl-auth.routes.public.enabled', false);
        $app['config']->set('nvl-auth.routes.account.enabled', false);
        $app['config']->set('nvl-auth.routes.management.enabled', false);
    }

    /**
     * Bind permissive host contracts for use-case tests.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->app->singleton(AuthManagementAccess::class, AllowAllManagementAccess::class);
        $this->app->singleton(AuthSubjectResolver::class, TestSubjectResolver::class);
    }

    /**
     * Create one conventional fixture user.
     */
    protected function user(string $email = 'user@example.test'): TestUser
    {
        return TestUser::query()->create([
            'name' => 'Test User',
            'email' => $email,
            'password' => 'correct-password',
        ]);
    }
}
