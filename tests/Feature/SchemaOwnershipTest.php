<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Models\PrincipalSecurityState;
use Nvl\Auth\Services\AuthDoctor;
use Nvl\Auth\Services\AuthSchemaManager;
use Nvl\Auth\Services\PrincipalSecurity;

beforeEach(function (): void {
    $driver = getenv('NVL_C1_TEST_DRIVER');
    if (in_array($driver, ['mysql', 'pgsql'], true)) {
        expect(DB::connection()->getDriverName())->toBe($driver);
    }
});

it('installs exactly the eighteen namespaced auth-owned tables', function (): void {
    $owned = [
        'nvl_auth_principal_security_states',
        AuthTables::Users,
        AuthTables::Permissions,
        AuthTables::Roles,
        AuthTables::ModelHasPermissions,
        AuthTables::ModelHasRoles,
        AuthTables::RoleHasPermissions,
        AuthTables::PersonalAccessTokens,
        AuthTables::PasswordResetTokens,
        AuthTables::Clients,
        AuthTables::ClientSessions,
        AuthTables::Invitations,
        AuthTables::Challenges,
        AuthTables::TotpCredentials,
        AuthTables::Passkeys,
        AuthTables::RecoveryCodes,
        AuthTables::SocialIdentities,
        AuthTables::Audits,
    ];

    foreach ($owned as $table) {
        expect(Schema::hasTable($table), $table)->toBeTrue();
    }

    foreach ([
        'users',
        'roles',
        'permissions',
        'model_has_permissions',
        'model_has_roles',
        'role_has_permissions',
        'personal_access_tokens',
        'password_reset_tokens',
        'auth_clients',
        'auth_audits',
        'auth_flows',
        'auth_sessions',
        'auth_deliveries',
        'auth_security_events',
        'auth_outbox_messages',
        'auth_maintenance_checkpoints',
    ] as $table) {
        expect(Schema::hasTable($table), $table)->toBeFalse();
    }
});

it('installs only enabled feature schema and safely installs later capabilities', function (): void {
    $features = require dirname(__DIR__, 2).'/database/migrations/2026_08_02_000000_nvl_auth_create_nvl_auth_tables.php';
    $identity = require dirname(__DIR__, 2).'/database/migrations/2026_08_01_000000_nvl_auth_create_nvl_auth_identity_tables.php';
    $features->down();
    $identity->down();
    config()->set('nvl-auth.enabled', false);
    config()->set('nvl-auth.migrations.install_all', false);

    foreach (AuthFeature::cases() as $feature) {
        config()->set("nvl-auth.features.{$feature->value}.enabled", false);
    }

    $identity->up();
    $features->up();

    expect(Schema::hasTable(AuthTables::Users))->toBeFalse()
        ->and(Schema::hasTable(AuthTables::Roles))->toBeFalse()
        ->and(Schema::hasTable(AuthTables::TotpCredentials))->toBeFalse();

    config()->set('nvl-auth.features.principal_management.enabled', true);
    config()->set('nvl-auth.features.totp.enabled', true);
    $plan = app(AuthSchemaManager::class)->execute();
    $applied = app(AuthSchemaManager::class)->execute(true);

    expect($plan['missing'])->toBe([AuthTables::Users, AuthTables::TotpCredentials])
        ->and($applied['created'])->toBe([AuthTables::Users, AuthTables::TotpCredentials])
        ->and(Schema::hasTable(AuthTables::Users))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::TotpCredentials))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::Passkeys))->toBeFalse();

    foreach (AuthFeature::cases() as $feature) {
        config()->set("nvl-auth.features.{$feature->value}.enabled", true);
    }

    app(AuthSchemaManager::class)->execute(true);
    config()->set('nvl-auth.migrations.install_all', true);
});

it('registers the feature-aware schema installation command', function (): void {
    $this->artisan('nvl:auth:schema', ['--format' => 'json'])
        ->assertSuccessful();
});

it('does not bypass host-owned migration mode during schema apply', function (): void {
    $features = require dirname(__DIR__, 2).'/database/migrations/2026_08_02_000000_nvl_auth_create_nvl_auth_tables.php';
    $features->down();
    config()->set('nvl-auth.migrations.enabled', false);

    expect(fn (): array => app(AuthSchemaManager::class)->execute(true))
        ->toThrow(
            RuntimeException::class,
            'Auth schema apply is unavailable while migrations are host-owned.',
        );

    config()->set('nvl-auth.migrations.enabled', true);
    $features->up();
});

it('rolls the complete package schema down and back up cleanly', function (): void {
    $features = require dirname(__DIR__, 2).'/database/migrations/2026_08_02_000000_nvl_auth_create_nvl_auth_tables.php';
    $identity = require dirname(__DIR__, 2).'/database/migrations/2026_08_01_000000_nvl_auth_create_nvl_auth_identity_tables.php';
    $deliveryContext = require dirname(__DIR__, 2).'/database/migrations/2026_08_12_000000_nvl_auth_add_auth_delivery_context_columns.php';
    $deliveryOutcomes = require dirname(__DIR__, 2).'/database/migrations/2026_08_28_000000_nvl_auth_add_invitation_delivery_outcomes.php';

    $deliveryOutcomes->down();
    $features->down();
    $identity->down();

    expect(Schema::hasTable(AuthTables::Users))->toBeFalse()
        ->and(Schema::hasTable(AuthTables::Clients))->toBeFalse()
        ->and(Schema::hasTable(AuthTables::Audits))->toBeFalse();

    $identity->up();
    $features->up();
    $deliveryContext->up();
    $deliveryOutcomes->up();

    expect(Schema::hasTable(AuthTables::Users))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::Roles))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::Clients))->toBeTrue()
        ->and(Schema::hasColumn(AuthTables::Invitations, 'active_key'))->toBeTrue()
        ->and(Schema::hasColumn(AuthTables::Invitations, 'delivery_status'))->toBeTrue()
        ->and(Schema::hasColumn(AuthTables::Invitations, 'delivery_failure_code'))->toBeTrue()
        ->and(Schema::hasColumn(AuthTables::Challenges, 'active_key'))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::Audits))->toBeTrue();
});

it('uses configured identity provider table names consistently during installation', function (): void {
    $identity = require dirname(__DIR__, 2).'/database/migrations/2026_08_01_000000_nvl_auth_create_nvl_auth_identity_tables.php';
    $identity->down();
    $configured = [
        'users' => 'custom_auth_users',
        'permissions' => 'custom_auth_permissions',
        'roles' => 'custom_auth_roles',
        'model_has_permissions' => 'custom_auth_model_has_permissions',
        'model_has_roles' => 'custom_auth_model_has_roles',
        'role_has_permissions' => 'custom_auth_role_has_permissions',
        'personal_access_tokens' => 'custom_auth_personal_access_tokens',
        'password_reset_tokens' => 'custom_auth_password_reset_tokens',
    ];

    foreach ($configured as $key => $table) {
        config()->set("nvl-auth.tables.{$key}", $table);
    }

    $identity->up();

    foreach ($configured as $table) {
        expect(Schema::hasTable($table), $table)->toBeTrue();
    }

    $identity->down();

    foreach ([
        'users' => AuthTables::Users,
        'permissions' => AuthTables::Permissions,
        'roles' => AuthTables::Roles,
        'model_has_permissions' => AuthTables::ModelHasPermissions,
        'model_has_roles' => AuthTables::ModelHasRoles,
        'role_has_permissions' => AuthTables::RoleHasPermissions,
        'personal_access_tokens' => AuthTables::PersonalAccessTokens,
        'password_reset_tokens' => AuthTables::PasswordResetTokens,
    ] as $key => $table) {
        config()->set("nvl-auth.tables.{$key}", $table);
    }

    $identity->up();
});

it('repairs partial mandatory security state without changing retained revisions', function (): void {
    $user = $this->user();
    $security = app(PrincipalSecurity::class);
    $security->revision($user);
    $user->getConnection()->transaction(fn () => $security->advance($user, 'security_containment'));
    Schema::table(AuthTables::PrincipalSecurityStates, function (Blueprint $table): void {
        $table->dropUnique('nvl_auth_principal_security_states_subject_unique');
        $table->dropColumn('updated_at');
    });
    $plan = app(AuthSchemaManager::class)->execute();
    expect($plan['outdated'][AuthTables::PrincipalSecurityStates])->toContain('updated_at');
    config(['nvl-auth.migrations.enabled' => false]);
    expect(fn () => app(AuthSchemaManager::class)->execute(true))->toThrow(RuntimeException::class, 'host-owned');
    expect(PrincipalSecurityState::query()->sole()->revision)->toBe(2);
    config(['nvl-auth.migrations.enabled' => true]);
    app(AuthSchemaManager::class)->execute(true);
    $migration = require dirname(__DIR__, 2).'/database/migrations/2026_10_27_000001_nvl_auth_create_principal_security_states.php';
    $migration->down();
    expect($security->revision($user))->toBe(2)
        ->and(Schema::hasIndex(AuthTables::PrincipalSecurityStates, 'nvl_auth_principal_security_states_subject_unique'))->toBeTrue();
});

it('rejects a malformed named security index without changing host data or schema', function (array $columns, string $operation): void {
    if ($columns === ['partial'] && DB::connection()->getDriverName() === 'mysql') {
        $this->markTestSkipped('MySQL does not support partial indexes.');
    }
    $user = $this->user();
    app(PrincipalSecurity::class)->revision($user);
    $state = PrincipalSecurityState::query()->sole();
    $state->forceFill(['revision' => 19])->save();
    $indexName = 'nvl_auth_principal_security_states_subject_unique';
    Schema::table(AuthTables::PrincipalSecurityStates, function (Blueprint $table) use ($columns, $indexName): void {
        $table->dropUnique($indexName);
        if ($columns !== ['partial']) {
            $table->unique($columns, $indexName);
        }
    });
    if ($columns === ['partial']) {
        DB::statement('CREATE UNIQUE INDEX nvl_auth_principal_security_states_subject_unique ON nvl_auth_principal_security_states (subject_type, subject_id) WHERE revision > 1');
    }
    if ($operation === 'migration') {
        Schema::table(AuthTables::PrincipalSecurityStates, fn (Blueprint $table) => $table->dropColumn('updated_at'));
    }
    $indexes = Schema::getIndexes(AuthTables::PrincipalSecurityStates);
    $columnNames = Schema::getColumnListing(AuthTables::PrincipalSecurityStates);
    $attributes = $state->refresh()->getRawOriginal();
    $definitionQuery = DB::connection()->getDriverName() === 'pgsql' ? 'select pg_get_indexdef(oid) as definition from pg_class where relname = ?' : 'select sql as definition from sqlite_master where name = ?';
    $definition = $columns === ['partial'] ? DB::select($definitionQuery, [$indexName]) : null;
    if ($operation === 'migration') {
        $migration = require dirname(__DIR__, 2).'/database/migrations/2026_10_27_000001_nvl_auth_create_principal_security_states.php';
        expect(fn () => $migration->up())->toThrow(RuntimeException::class, 'subject index');
    } else {
        expect(app(AuthSchemaManager::class)->execute()['missing_indexes'][AuthTables::PrincipalSecurityStates] ?? [])->toContain($indexName);
        expect(collect(app(AuthDoctor::class)->inspect())->firstWhere('name', 'schema.'.AuthTables::PrincipalSecurityStates.'.index.'.$indexName))->toMatchArray(['passed' => false]);
    }
    expect(Schema::getIndexes(AuthTables::PrincipalSecurityStates))->toBe($indexes)
        ->and(Schema::getColumnListing(AuthTables::PrincipalSecurityStates))->toBe($columnNames)
        ->and($state->refresh()->getRawOriginal())->toBe($attributes);
    if ($definition !== null) {
        expect(DB::select($definitionQuery, [$indexName]))->toEqual($definition);
    }
})->with(['primary id' => [['id']], 'subject id only' => [['subject_id']], 'reversed columns' => [['subject_id', 'subject_type']], 'partial constraint' => [['partial']]])->with(['migration', 'readiness']);
