<?php

declare(strict_types=1);

use Nvl\Auth\Adapters\Laravel\LaravelPrincipalSessionContainment;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\ConfiguredPrincipalAttributeMapper;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Services\PackagePermissionCatalog;
use Nvl\Auth\Services\PackageRoleTemplates;

return [
    /*
    |--------------------------------------------------------------------------
    | Package ingress and storage
    |--------------------------------------------------------------------------
    */
    'enabled' => env('NVL_AUTH_ENABLED', true),
    'connection' => env('NVL_AUTH_DB_CONNECTION'),
    'migrations' => [
        'enabled' => true,
        'load_when_disabled' => false,
        'install_all' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Host authentication integration
    |--------------------------------------------------------------------------
    */
    'guard' => env('NVL_AUTH_GUARD', 'web'),
    'password_broker' => env('NVL_AUTH_PASSWORD_BROKER'),
    'identifier' => env('NVL_AUTH_IDENTIFIER', 'email'),
    'services' => [
        'system_mutation_access' => DenySystemMutationAccess::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Feature ownership
    |--------------------------------------------------------------------------
    |
    | A disabled feature exposes no routes and every public Action fails closed.
    | Feature data is retained until explicitly revoked or pruned.
    |
    */
    'features' => [
        'authentication' => [
            'enabled' => env('NVL_AUTH_AUTHENTICATION_ENABLED', true),
            'routes' => ['public' => ['enabled' => false], 'account' => ['enabled' => false]],
            'services' => [
                'subject_resolver' => null,
                'identifier_resolver' => null,
                'login_metadata_recorder' => null,
                'eligibility' => null,
            ],
            'settings' => [],
        ],
        'principal_management' => [
            'enabled' => env('NVL_AUTH_PRINCIPAL_MANAGEMENT_ENABLED', true),
            'routes' => ['account' => ['enabled' => false], 'management' => ['enabled' => false]],
            'models' => ['user' => User::class],
            'services' => [
                'attribute_mapper' => ConfiguredPrincipalAttributeMapper::class,
                'account_confirmation' => null,
                'session_containment' => LaravelPrincipalSessionContainment::class,
            ],
            'settings' => [
                'use_as_auth_model' => true,
                'default_locale' => env('APP_LOCALE', 'en'),
                'default_timezone' => 'UTC',
                'per_page' => 25,
                'maximum_per_page' => 100,
                'suggestion_limit' => 20,
                'attributes' => [
                    'id' => 'id',
                    'name' => 'name',
                    'email' => 'email',
                    'email_verified_at' => 'email_verified_at',
                    'password' => 'password',
                    'active' => 'is_active',
                    'locale' => 'locale',
                    'timezone' => 'timezone',
                    'profile' => 'profile',
                    'preferences' => 'preferences',
                    'last_login_at' => 'last_login_at',
                    'last_login_ip' => 'last_login_ip',
                    'locked_until' => 'locked_until',
                    'remember_token' => 'remember_token',
                    'created_at' => 'created_at',
                    'updated_at' => 'updated_at',
                    'deleted_at' => 'deleted_at',
                ],
            ],
        ],
        'password' => [
            'enabled' => env('NVL_AUTH_PASSWORD_ENABLED', true),
            'routes' => ['public' => ['enabled' => false], 'account' => ['enabled' => false]],
            'services' => ['updater' => null],
            'settings' => ['reset_ttl_minutes' => 60],
        ],
        'email_verification' => [
            'enabled' => env('NVL_AUTH_EMAIL_VERIFICATION_ENABLED', false),
            'routes' => ['public' => ['enabled' => false], 'account' => ['enabled' => false]],
            'settings' => ['ttl_minutes' => 60],
        ],
        'magic_links' => [
            'enabled' => env('NVL_AUTH_MAGIC_LINKS_ENABLED', false),
            'routes' => ['public' => ['enabled' => false]],
            'settings' => ['ttl_minutes' => 15, 'max_attempts' => 5, 'fallback_code_digits' => 6],
        ],
        'security_codes' => [
            'enabled' => env('NVL_AUTH_SECURITY_CODES_ENABLED', false),
            'routes' => ['public' => ['enabled' => false]],
            'settings' => ['ttl_minutes' => 10, 'digits' => 6, 'max_attempts' => 5],
        ],
        'invitations' => [
            'enabled' => env('NVL_AUTH_INVITATIONS_ENABLED', false),
            'routes' => ['public' => ['enabled' => false], 'management' => ['enabled' => false]],
            'services' => [
                'subject_resolver' => null,
                'registration_mapper' => null,
            ],
            'settings' => ['ttl_hours' => 72, 'resend_cooldown_seconds' => 60],
        ],
        'totp' => [
            'enabled' => env('NVL_AUTH_TOTP_ENABLED', false),
            'routes' => ['account' => ['enabled' => false]],
            'settings' => [
                'issuer' => env('APP_NAME', 'Laravel'),
                'algorithm' => 'sha1',
                'digits' => 6,
                'period_seconds' => 30,
                'window' => 1,
                'secret_length' => 32,
            ],
        ],
        'passkeys' => [
            'enabled' => env('NVL_AUTH_PASSKEYS_ENABLED', false),
            'routes' => ['public' => ['enabled' => false], 'account' => ['enabled' => false]],
            'services' => ['ceremony' => null],
            'settings' => [
                'relying_party_id' => env('NVL_AUTH_PASSKEY_RP_ID'),
                'relying_party_name' => env('NVL_AUTH_PASSKEY_RP_NAME', env('APP_NAME', 'Laravel')),
                'origins' => array_values(array_filter(explode(',', (string) env('NVL_AUTH_PASSKEY_ORIGINS', '')))),
                'allow_subdomains' => false,
                'timeout_ms' => 60_000,
                'ceremony_ttl_seconds' => 300,
                'max_credentials_per_subject' => 20,
                'require_user_verification' => true,
                'resident_key' => 'required',
                'username_attribute' => env('NVL_AUTH_PASSKEY_USERNAME_ATTRIBUTE', env('NVL_AUTH_IDENTIFIER', 'email')),
                'display_name_attribute' => env('NVL_AUTH_PASSKEY_DISPLAY_NAME_ATTRIBUTE', 'name'),
                'user_handle_key' => env('NVL_AUTH_PASSKEY_USER_HANDLE_KEY'),
            ],
        ],
        'recovery_codes' => [
            'enabled' => env('NVL_AUTH_RECOVERY_CODES_ENABLED', false),
            'routes' => ['account' => ['enabled' => false]],
            'settings' => ['count' => 8, 'length' => 10],
        ],
        'social_identities' => [
            'enabled' => env('NVL_AUTH_SOCIAL_IDENTITIES_ENABLED', false),
            'routes' => ['public' => ['enabled' => false], 'account' => ['enabled' => false]],
            'services' => ['provider' => null, 'subject_resolver' => null],
            'settings' => ['providers' => []],
        ],
        'clients' => [
            'enabled' => env('NVL_AUTH_CLIENTS_ENABLED', false),
            'routes' => ['public' => ['enabled' => false], 'management' => ['enabled' => false]],
            'settings' => [],
        ],
        'sessions' => [
            'enabled' => env('NVL_AUTH_SESSIONS_ENABLED', true),
            'routes' => ['account' => ['enabled' => false]],
            'settings' => [],
        ],
        'api_tokens' => [
            'enabled' => env('NVL_AUTH_API_TOKENS_ENABLED', false),
            'routes' => ['account' => ['enabled' => false]],
            'services' => ['manager' => null, 'ability_provider' => null],
            'models' => ['personal_access_token' => PersonalAccessToken::class],
            'settings' => ['abilities' => [], 'namespace' => 'nvl-auth'],
        ],
        'rbac' => [
            'enabled' => env('NVL_AUTH_RBAC_ENABLED', true),
            'routes' => ['management' => ['enabled' => false]],
            'models' => [
                'role' => Role::class,
                'permission' => Permission::class,
                'principal' => null,
            ],
            'services' => [
                'permission_catalogs' => [PackagePermissionCatalog::class],
                'role_templates' => [PackageRoleTemplates::class],
                'principal_access' => EloquentRbacPrincipalAccess::class,
            ],
            'settings' => [
                'guard' => env('NVL_AUTH_RBAC_GUARD', 'web'),
                'super_admin_role' => env('NVL_AUTH_SUPER_ADMIN_ROLE', 'super-admin'),
                'use_package_storage' => true,
                'role_option_limit' => 50,
                'permission_option_limit' => 100,
                'identifier_resolution_limit' => 100,
            ],
        ],
        'audit' => [
            'enabled' => env('NVL_AUTH_AUDIT_ENABLED', true),
            'routes' => ['management' => ['enabled' => false]],
            'services' => ['recorder' => null],
            'settings' => ['capture_ip' => true, 'capture_user_agent' => true],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Optional HTTP API
    |--------------------------------------------------------------------------
    */
    'routes' => [
        'enabled' => env('NVL_AUTH_ROUTES_ENABLED', false),
        'prefix' => env('NVL_AUTH_ROUTES_PREFIX', 'api/v1/auth'),
        'middleware' => ['api'],
        'public' => ['enabled' => false, 'middleware' => ['throttle:nvl-auth-public']],
        'account' => ['enabled' => false, 'middleware' => ['auth', 'throttle:nvl-auth-account']],
        'management' => ['enabled' => false, 'middleware' => ['auth', 'throttle:nvl-auth-management']],
    ],

    /*
    |--------------------------------------------------------------------------
    | Extensible use-case pipelines
    |--------------------------------------------------------------------------
    */
    'pipelines' => [
        'login' => [],
        'logout' => [],
        'password_reset_requested' => [],
        'password_reset' => [],
        'invitation_issued' => [],
        'invitation_accepted' => [],
        'client_started' => [],
        'api_token_issued' => [],
    ],

    'cleanup' => [
        'retention_days' => env('NVL_AUTH_RETENTION_DAYS', 30),
    ],

    'adoption' => [
        'maximum_manifest_bytes' => 1_048_576,
        'maximum_records' => 10_000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Configurable identity and provider table names
    |--------------------------------------------------------------------------
    |
    | These names are intentionally namespaced. Changing them after installation
    | requires a coordinated schema and data migration.
    |
    */
    'tables' => [
        'users' => AuthTables::Users,
        'roles' => AuthTables::Roles,
        'permissions' => AuthTables::Permissions,
        'model_has_permissions' => AuthTables::ModelHasPermissions,
        'model_has_roles' => AuthTables::ModelHasRoles,
        'role_has_permissions' => AuthTables::RoleHasPermissions,
        'personal_access_tokens' => AuthTables::PersonalAccessTokens,
        'password_reset_tokens' => AuthTables::PasswordResetTokens,
    ],
];
