<?php

declare(strict_types=1);

use Laravel\Sanctum\Sanctum;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Tests\Fixtures\HostPersonalAccessToken;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Data\Services\TypeScriptSourceRegistry;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

it('remains passive over host integrations and migration inventory when globally disabled', function (): void {
    $authMigrationPath = realpath(dirname(__DIR__, 2).'/database/migrations');

    expect(config('auth.providers.users.model'))->toBe(TestUser::class)
        ->and(config('auth.passwords.users.table'))->toBe('host_password_reset_tokens')
        ->and(config('permission.models.role'))->toBe(Role::class)
        ->and(config('permission.models.permission'))->toBe(Permission::class)
        ->and(config('permission.table_names.roles'))->toBe('host_roles')
        ->and(Sanctum::personalAccessTokenModel())->toBe(HostPersonalAccessToken::class)
        ->and(app()->bound(TypeScriptSourceRegistry::class))->toBeTrue()
        ->and(app('migrator')->paths())->not->toContain($authMigrationPath);

    config()->set('nvl-auth.enabled', true);
    config()->set('nvl-auth.features.api_tokens.enabled', false);
    (new AuthServiceProvider(app()))->boot(
        app(AuthConfiguration::class),
        app(TypeScriptSourceRegistry::class),
    );

    expect(Sanctum::personalAccessTokenModel())->toBe(HostPersonalAccessToken::class);
});
