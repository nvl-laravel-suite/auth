<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Adapters\ApiTokens\SanctumApiTokenManager;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\LaravelGateAuthManagementAccess;

it('reports the complete feature inventory in table and JSON formats', function (): void {
    $this->artisan('nvl:auth:features')->assertSuccessful();
    $this->artisan('nvl:auth:features', ['--format' => 'json'])
        ->expectsOutputToContain('"authentication"')
        ->assertSuccessful();
    $this->artisan('nvl:auth:features', ['--format' => 'yaml'])->assertExitCode(2);
});

it('passes readiness for the default lean profile and fails missing dependencies', function (): void {
    $this->artisan('nvl:auth:doctor')->assertSuccessful();
    $this->artisan('nvl:auth:doctor', ['--format' => 'json'])
        ->expectsOutputToContain('"ready": true')
        ->assertSuccessful();
    $this->artisan('nvl:auth:doctor', ['--format' => 'yaml'])->assertExitCode(2);

    config()->set('nvl-auth.features.authentication.enabled', false);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Feature [password] requires [authentication].')
        ->assertFailed();
});

it('registers timestamp-aware migration publishing and warns about duplicate ownership', function (): void {
    $migrationPath = realpath(dirname(__DIR__, 2).'/database/migrations');
    $publishableMigrationPaths = array_map(
        static fn (string $path): string|false => realpath($path),
        ServiceProvider::publishableMigrationPaths(),
    );

    expect(AuthServiceProvider::pathsToPublish(
        AuthServiceProvider::class,
        'auth-migrations',
    ))->not->toBeEmpty()
        ->and($publishableMigrationPaths)->toContain($migrationPath);

    $published = database_path(
        'migrations/2099_01_01_000000_create_nvl_auth_identity_tables.php',
    );
    file_put_contents($published, "<?php\n");

    try {
        $this->artisan('nvl:auth:doctor')
            ->expectsOutputToContain('Automatic vendor migration loading overlaps')
            ->assertSuccessful();
        $this->artisan('nvl:auth:doctor', ['--strict' => true])
            ->expectsOutputToContain('create_nvl_auth_identity_tables')
            ->assertFailed();
    } finally {
        unlink($published);
    }
});

it('fails readiness when passkeys are enabled without valid relying-party policy', function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', true);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('The configured or built-in passkey ceremony implementation could not be resolved.')
        ->expectsOutputToContain('Passkeys require HTTPS origins matching the relying-party ID.')
        ->assertFailed();
});

it('passes passkey readiness with the built-in ceremony implementation', function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', true);
    config()->set('nvl-auth.features.passkeys.settings.relying_party_id', 'auth-package.test');
    config()->set('nvl-auth.features.passkeys.settings.origins', ['https://auth-package.test']);

    $this->artisan('nvl:auth:doctor')->assertSuccessful();
});

it('reports invalid built-in passkey key and ceremony timing configuration', function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', true);
    config()->set('nvl-auth.features.passkeys.settings.relying_party_id', 'auth-package.test');
    config()->set('nvl-auth.features.passkeys.settings.origins', ['https://auth-package.test']);
    config()->set('nvl-auth.features.passkeys.settings.user_handle_key', 'too-short');
    config()->set('nvl-auth.features.passkeys.settings.timeout_ms', 120_000);
    config()->set('nvl-auth.features.passkeys.settings.ceremony_ttl_seconds', 60);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Passkeys require at least 32 bytes of user-handle key material')
        ->expectsOutputToContain('Passkey ceremony TTL must be 60 to 900 seconds and cover the browser timeout.')
        ->assertFailed();
});

it('validates optional Sanctum storage without making Sanctum a core dependency', function (): void {
    config()->set('nvl-auth.features.api_tokens.enabled', true);
    config()->set('nvl-auth.features.api_tokens.services.manager', SanctumApiTokenManager::class);
    config()->set('nvl-auth.features.api_tokens.settings.abilities', ['profile:read']);

    $this->artisan('nvl:auth:doctor')->assertSuccessful();

    Schema::drop('nvl_auth_personal_access_tokens');

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('The Sanctum adapter requires package-owned nvl_auth_personal_access_tokens storage.')
        ->assertFailed();
});

it('does not resolve invalid dormant adapters during readiness checks', function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', false);
    config()->set('nvl-auth.features.passkeys.services.ceremony', stdClass::class);
    config()->set('nvl-auth.features.social_identities.enabled', false);
    config()->set('nvl-auth.features.social_identities.services.provider', stdClass::class);

    $this->artisan('nvl:auth:doctor')->assertSuccessful();
    $this->artisan('nvl:auth:doctor', ['--strict' => true])
        ->expectsOutputToContain('Disabled features must not retain integration configuration')
        ->assertFailed();
});

it('fails readiness for invalid pipelines and management abilities without package RBAC or Gate policy', function (): void {
    config()->set('nvl-auth.pipelines.login', [stdClass::class]);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Auth pipelines contain an unknown pipeline or invalid stage.')
        ->assertFailed();

    config()->set('nvl-auth.pipelines.login', []);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.management.enabled', true);
    config()->set('nvl-auth.features.clients.enabled', true);
    config()->set('nvl-auth.features.clients.routes.management.enabled', true);
    config()->set('nvl-auth.features.rbac.enabled', false);
    $this->app->forgetInstance(AuthManagementAccess::class);
    $this->app->singleton(AuthManagementAccess::class, LaravelGateAuthManagementAccess::class);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Management routes require package RBAC or Laravel Gate authorization for [nvl-auth.clients.viewAny].')
        ->assertFailed();
});
