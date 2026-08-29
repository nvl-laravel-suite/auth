<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Adapters\ApiTokens\SanctumApiTokenManager;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\LaravelGateAuthManagementAccess;

it('reports the complete feature inventory in table and JSON formats', function (): void {
    $this->artisan('nvl:auth:features')->assertSuccessful();
    $this->artisan('nvl:auth:features', ['--format' => 'json'])
        ->expectsOutputToContain('"authentication"')
        ->assertSuccessful();
    $this->artisan('nvl:auth:features', ['--format' => 'yaml'])->assertExitCode(2);
});

it('reports Auth schema plans in text and JSON formats', function (): void {
    $this->artisan('nvl:auth:schema')->assertSuccessful();
    $this->artisan('nvl:auth:schema', ['--format' => 'json'])
        ->expectsOutputToContain('"mode": "plan"')
        ->assertSuccessful();

    Schema::drop(AuthTables::PersonalAccessTokens);

    $this->artisan('nvl:auth:schema')
        ->expectsOutputToContain(AuthTables::PersonalAccessTokens)
        ->assertSuccessful();

    expect(static fn (): int => Artisan::call('nvl:auth:schema', ['--format' => 'yaml']))
        ->toThrow(InvalidArgumentException::class, 'format must be text or json');
});

it('rejects unsafe principal adoption command input before invoking adoption', function (): void {
    expect(static fn (): int => Artisan::call('nvl:auth:adopt-principals', [
        'manifest' => 'missing.json',
        '--format' => 'yaml',
    ]))->toThrow(InvalidArgumentException::class, 'format must be text or json');

    expect(static fn (): int => Artisan::call('nvl:auth:adopt-principals', [
        'manifest' => ' ',
    ]))->toThrow(InvalidArgumentException::class, 'manifest is required');

    config()->set('nvl-auth.adoption.maximum_manifest_bytes', 0);
    expect(static fn (): int => Artisan::call('nvl:auth:adopt-principals', [
        'manifest' => 'missing.json',
    ]))->toThrow(InvalidArgumentException::class, 'must be a positive integer');

    config()->set('nvl-auth.adoption.maximum_manifest_bytes', 1_048_576);
    expect(static fn (): int => Artisan::call('nvl:auth:adopt-principals', [
        'manifest' => 'missing.json',
    ]))->toThrow(InvalidArgumentException::class, 'missing or too large');

    $invalidJson = tempnam(sys_get_temp_dir(), 'nvl-auth-invalid-json-');
    $scalarJson = tempnam(sys_get_temp_dir(), 'nvl-auth-scalar-json-');

    expect($invalidJson)->toBeString()
        ->and($scalarJson)->toBeString();

    file_put_contents($invalidJson, '{');
    file_put_contents($scalarJson, 'true');

    try {
        expect(static fn (): int => Artisan::call('nvl:auth:adopt-principals', [
            'manifest' => $invalidJson,
        ]))->toThrow(InvalidArgumentException::class, 'is not valid JSON')
            ->and(static fn (): int => Artisan::call('nvl:auth:adopt-principals', [
                'manifest' => $scalarJson,
            ]))->toThrow(InvalidArgumentException::class, 'must be a JSON object');
    } finally {
        unlink($invalidJson);
        unlink($scalarJson);
    }
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

it('fails readiness for unsafe invitation delivery metadata allowlists', function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', [
        'member_id',
        'api_token',
        'active_key',
    ]);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Invitation delivery metadata keys must be a bounded safe allowlist.')
        ->assertFailed();

    config()->set(
        'nvl-auth.features.invitations.settings.delivery_metadata_keys',
        array_map(static fn (int $index): string => "field_{$index}", range(1, 51)),
    );

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Invitation delivery metadata keys must be a bounded safe allowlist.')
        ->assertFailed();
});

it('fails readiness when Auth delivery correlation indexes are missing', function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.magic_links.enabled', true);

    Schema::table(AuthTables::Invitations, function (Blueprint $table): void {
        $table->dropIndex('nvl_auth_invitations_context_hash_index');
    });

    try {
        $this->artisan('nvl:auth:doctor')
            ->expectsOutputToContain('nvl_auth_invitations_context_hash_index')
            ->assertFailed();
    } finally {
        $migration = require dirname(__DIR__, 2).'/database/migrations/2026_08_12_000000_add_auth_delivery_context_columns.php';
        $migration->up();
    }

    Schema::table(AuthTables::Challenges, function (Blueprint $table): void {
        $table->dropUnique('nvl_auth_challenges_secondary_secret_hash_unique');
    });

    try {
        $this->artisan('nvl:auth:doctor')
            ->expectsOutputToContain('nvl_auth_challenges_secondary_secret_hash_unique')
            ->assertFailed();
    } finally {
        $migration = require dirname(__DIR__, 2).'/database/migrations/2026_08_12_000000_add_auth_delivery_context_columns.php';
        $migration->up();
    }

    config()->set('nvl-auth.features.invitations.enabled', false);
    config()->set('nvl-auth.features.magic_links.enabled', false);

    $this->artisan('nvl:auth:doctor')->assertSuccessful();
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
        ->and(AuthServiceProvider::pathsToPublish(
            AuthServiceProvider::class,
            'auth-adoption',
        ))->toHaveCount(1)
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

    Schema::drop(AuthTables::PersonalAccessTokens);

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
