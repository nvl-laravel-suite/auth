<?php

declare(strict_types=1);
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
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
    ],

    /*
    |--------------------------------------------------------------------------
    | Host authentication integration
    |--------------------------------------------------------------------------
    */
    'guard' => env('NVL_AUTH_GUARD', 'web'),
    'password_broker' => env('NVL_AUTH_PASSWORD_BROKER'),
    'identifier' => env('NVL_AUTH_IDENTIFIER', 'email'),

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
            'services' => ['subject_resolver' => null, 'identifier_resolver' => null],
            'settings' => [],
        ],
        'principal_management' => [
            'enabled' => env('NVL_AUTH_PRINCIPAL_MANAGEMENT_ENABLED', true),
            'routes' => ['account' => ['enabled' => false], 'management' => ['enabled' => false]],
            'models' => ['user' => User::class],
            'settings' => [
                'use_as_auth_model' => true,
                'default_locale' => env('APP_LOCALE', 'en'),
                'default_timezone' => 'UTC',
                'per_page' => 25,
                'maximum_per_page' => 100,
                'suggestion_limit' => 20,
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
            'settings' => ['ttl_minutes' => 15, 'max_attempts' => 5],
        ],
        'security_codes' => [
            'enabled' => env('NVL_AUTH_SECURITY_CODES_ENABLED', false),
            'routes' => ['public' => ['enabled' => false]],
            'settings' => ['ttl_minutes' => 10, 'digits' => 6, 'max_attempts' => 5],
        ],
        'invitations' => [
            'enabled' => env('NVL_AUTH_INVITATIONS_ENABLED', false),
            'routes' => ['public' => ['enabled' => false], 'management' => ['enabled' => false]],
            'services' => ['subject_resolver' => null],
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
            ],
            'services' => [
                'permission_catalogs' => [PackagePermissionCatalog::class],
                'role_templates' => [PackageRoleTemplates::class],
            ],
            'settings' => [
                'guard' => env('NVL_AUTH_RBAC_GUARD', 'web'),
                'super_admin_role' => env('NVL_AUTH_SUPER_ADMIN_ROLE', 'super-admin'),
                'use_package_storage' => true,
            ],
        ],
        'audit' => [
            'enabled' => env('NVL_AUTH_AUDIT_ENABLED', true),
            'routes' => ['management' => ['enabled' => false]],
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
        'users' => 'nvl_auth_users',
        'roles' => 'nvl_auth_roles',
        'permissions' => 'nvl_auth_permissions',
        'model_has_permissions' => 'nvl_auth_model_has_permissions',
        'model_has_roles' => 'nvl_auth_model_has_roles',
        'role_has_permissions' => 'nvl_auth_role_has_permissions',
        'personal_access_tokens' => 'nvl_auth_personal_access_tokens',
        'password_reset_tokens' => 'nvl_auth_password_reset_tokens',
    ],
];
