<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Nvl\Auth\Models\User;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Support\Providers\LocaleServiceProvider;
use Orchestra\Testbench\TestCase;

/** Core integration with no optional Auth adapter provider registered. */
abstract class CoreOnlyTestCase extends TestCase
{
    use DatabaseMigrations;

    protected function getPackageProviders($app): array
    {
        return [LocaleServiceProvider::class, AuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set([
            'app.key' => 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
            'hashing.bcrypt.rounds' => 4,
            'auth.timebox_duration' => 0,
            'auth.defaults.guard' => 'web',
            'auth.guards.web' => ['driver' => 'session', 'provider' => 'users'],
            'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
            'auth.passwords.users' => ['provider' => 'users', 'table' => 'nvl_auth_password_reset_tokens', 'expire' => 60, 'throttle' => 0],
            'nvl-auth.features.principal_management.models.user' => User::class,
            'nvl-auth.features.rbac.enabled' => false,
            'nvl-auth.features.api_tokens.enabled' => false,
            'nvl-auth.features.passkeys.enabled' => false,
            'nvl-auth.features.totp.enabled' => false,
            'nvl-auth.features.recovery_codes.enabled' => false,
            'nvl-auth.features.social_identities.enabled' => false,
            'nvl-auth.migrations.install_all' => false,
        ]);
    }
}
