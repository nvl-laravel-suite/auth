<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Enums\AuthFeature;

it('installs exactly the seventeen namespaced auth-owned tables', function (): void {
    $owned = [
        'nvl_auth_users',
        'nvl_auth_permissions',
        'nvl_auth_roles',
        'nvl_auth_model_has_permissions',
        'nvl_auth_model_has_roles',
        'nvl_auth_role_has_permissions',
        'nvl_auth_personal_access_tokens',
        'nvl_auth_password_reset_tokens',
        'nvl_auth_clients',
        'nvl_auth_client_sessions',
        'nvl_auth_invitations',
        'nvl_auth_challenges',
        'nvl_auth_totp_credentials',
        'nvl_auth_passkeys',
        'nvl_auth_recovery_codes',
        'nvl_auth_social_identities',
        'nvl_auth_audits',
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

it('installs the complete schema even when ingress and every feature are disabled', function (): void {
    config()->set('nvl-auth.enabled', false);

    foreach (AuthFeature::cases() as $feature) {
        config()->set("nvl-auth.features.{$feature->value}.enabled", false);
    }

    expect(Schema::hasTable('nvl_auth_users'))->toBeTrue()
        ->and(Schema::hasTable('nvl_auth_roles'))->toBeTrue()
        ->and(Schema::hasTable('nvl_auth_clients'))->toBeTrue()
        ->and(Schema::hasTable('nvl_auth_audits'))->toBeTrue();
});

it('rolls the complete package schema down and back up cleanly', function (): void {
    $features = require dirname(__DIR__, 2).'/database/migrations/2026_08_02_000000_create_nvl_auth_tables.php';
    $identity = require dirname(__DIR__, 2).'/database/migrations/2026_08_01_000000_create_nvl_auth_identity_tables.php';

    $features->down();
    $identity->down();

    expect(Schema::hasTable('nvl_auth_users'))->toBeFalse()
        ->and(Schema::hasTable('nvl_auth_clients'))->toBeFalse()
        ->and(Schema::hasTable('nvl_auth_audits'))->toBeFalse();

    $identity->up();
    $features->up();

    expect(Schema::hasTable('nvl_auth_users'))->toBeTrue()
        ->and(Schema::hasTable('nvl_auth_roles'))->toBeTrue()
        ->and(Schema::hasTable('nvl_auth_clients'))->toBeTrue()
        ->and(Schema::hasColumn('nvl_auth_invitations', 'active_key'))->toBeTrue()
        ->and(Schema::hasColumn('nvl_auth_challenges', 'active_key'))->toBeTrue()
        ->and(Schema::hasTable('nvl_auth_audits'))->toBeTrue();
});

it('uses configured identity provider table names consistently during installation', function (): void {
    $identity = require dirname(__DIR__, 2).'/database/migrations/2026_08_01_000000_create_nvl_auth_identity_tables.php';
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
        'users' => 'nvl_auth_users',
        'permissions' => 'nvl_auth_permissions',
        'roles' => 'nvl_auth_roles',
        'model_has_permissions' => 'nvl_auth_model_has_permissions',
        'model_has_roles' => 'nvl_auth_model_has_roles',
        'role_has_permissions' => 'nvl_auth_role_has_permissions',
        'personal_access_tokens' => 'nvl_auth_personal_access_tokens',
        'password_reset_tokens' => 'nvl_auth_password_reset_tokens',
    ] as $key => $table) {
        config()->set("nvl-auth.tables.{$key}", $table);
    }

    $identity->up();
});
