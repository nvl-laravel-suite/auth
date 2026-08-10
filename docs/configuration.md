# Configuration

Publish the canonical configuration with:

```bash
php artisan vendor:publish --tag=auth-config
```

## Package, identity, and storage

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | global functional ingress switch |
| `connection` | `null` | package operational database connection |
| `migrations.enabled` | `true` | load feature-aware package migrations |
| `migrations.load_when_disabled` | `false` | explicitly load migrations while global Auth ingress is disabled |
| `migrations.install_all` | `false` | force the full inventory only in controlled test/rehearsal environments |
| `guard` | `web` | stateful Laravel guard used by browser authentication |
| `password_broker` | provider default | Laravel password broker configured to the package token table |
| `identifier` | `email` | login and broker credential attribute |
| `features.principal_management.models.user` | package User | concrete/extensible principal class |
| `features.principal_management.settings.use_as_auth_model` | `true` | configure the selected guard provider to use the package User |
| `features.rbac.models.role` | package Role | Spatie-compatible role class |
| `features.rbac.models.permission` | package Permission | Spatie-compatible permission class |
| `features.api_tokens.models.personal_access_token` | package token | Sanctum token class |

Choose the connection and table layout before installation. Changing either
after rows exist is a coordinated data migration, not a runtime feature toggle.
When `enabled=false`, Auth leaves the host Laravel user provider, password
broker, Spatie Permission storage, Sanctum token model, and migration inventory
unchanged. Set `migrations.load_when_disabled=true` only for an intentional
schema-first rollout. Do not enable `migrations.install_all` in a normal host
deployment; use `nvl:auth:schema` when a later feature needs new tables.

## Feature shape

```php
'features' => [
    'feature_name' => [
        'enabled' => false,
        'routes' => [
            'public' => ['enabled' => false],
            'account' => ['enabled' => false],
            'management' => ['enabled' => false],
        ],
        'models' => [],
        'services' => [],
        'settings' => [],
    ],
],
```

Every feature uses a hard boolean. Disabling it retains its data but blocks
normal direct Actions and routes. Unknown scalar modes are rejected.

## Principal management

The default package User is immediately usable. Configuration controls the
model class, Laravel auth-provider integration, physical principal attributes,
default locale/timezone, pagination maximum, and suggestion limit.

```php
'principal_management' => [
    'enabled' => true,
    'routes' => [
        'account' => ['enabled' => true],
        'management' => ['enabled' => true],
    ],
    'models' => ['user' => App\Models\User::class], // subclass package User
    'services' => [
        'attribute_mapper' => Nvl\Auth\Services\ConfiguredPrincipalAttributeMapper::class,
    ],
    'settings' => [
        'use_as_auth_model' => true,
        'default_locale' => 'en',
        'default_timezone' => 'UTC',
        'per_page' => 25,
        'maximum_per_page' => 100,
        'suggestion_limit' => 20,
        'attributes' => [
            'id' => 'id',
            'name' => 'name',
            'email' => 'email',
            'active' => 'active',
            'profile' => 'auth_profile',
            'preferences' => 'auth_preferences',
            // Keep every other key from the published configuration.
        ],
    ],
],
```

Set `use_as_auth_model=false` only when intentionally integrating a different
Laravel user provider; then the configured resolvers and compatible model
contracts become the application's responsibility.

The `attributes` map must explicitly retain all canonical keys from the
published configuration. Package models, Actions, validation, authentication,
login metadata, and Doctor use the map. Column names must be unique safe
identifiers. A custom `PrincipalAttributeMapper` may replace the configured
mapper, but its mapping must remain consistent with the model's configured
attribute map.

Principal write Actions pass the DTO's complete validated array through this
mapper and into Eloquent mass assignment. Partial mutation DTOs represent
missing properties with `Optional`, so an omitted field is never rewritten to
a default or `null`; explicit nullable values remain intentional updates.

Never map a column to the name of an Eloquent relationship. Also ensure the
physical principal table has no otherwise-unused column with that relationship
name: Eloquent attributes shadow relations even when the package map points
elsewhere. `nvl:auth:doctor` detects these physical collisions.

## Routes

```php
'routes' => [
    'enabled' => true,
    'prefix' => 'api/v1/auth',
    'middleware' => ['api'],
    'public' => [
        'enabled' => true,
        'middleware' => ['throttle:nvl-auth-public'],
    ],
    'account' => [
        'enabled' => true,
        'middleware' => ['auth:sanctum', 'throttle:nvl-auth-account'],
    ],
    'management' => [
        'enabled' => true,
        'middleware' => ['auth:sanctum', 'throttle:nvl-auth-management'],
    ],
],
```

The package adds its own feature middleware. Browser cookie login/logout needs
a session-starting stack such as `web` or correctly configured Sanctum stateful
middleware; a plain stateless `api` stack cannot persist a browser login.

## Feature-specific settings

| Feature | Important settings/services |
|---|---|
| authentication | optional identifier/subject resolvers and successful-login metadata recorder |
| principal management | User class, auth-provider switch, attribute mapper/columns, locale/timezone, page/suggestion limits |
| password | optional updater, reset TTL |
| email verification | TTL |
| magic links | TTL and maximum attempts |
| security codes | TTL, digits, maximum attempts |
| invitations | optional subject resolver, TTL, resend cooldown |
| TOTP | issuer, algorithm, digits, period, window, secret length |
| passkeys | optional ceremony override, RP/origin/user-verification policy |
| recovery codes | batch count and code length |
| social identities | acquisition/subject resolvers and provider allowlist |
| API tokens | token model/manager, ability provider/catalog, namespace |
| RBAC | Role/Permission classes, catalog/template providers, guard, super-admin role |
| audit | recorder implementation, IP and user-agent capture |

## Passkeys

No application ceremony adapter is required. When `services.ceremony` is
`null`, the package selects its maintained WebAuthn implementation. Configure a
hostname-only `relying_party_id`, explicit HTTPS `origins`, relying-party name,
timeout/ceremony TTL, credential limit, user-verification/resident-key policy,
display attributes, and a stable user-handle key (or stable `APP_KEY`).

## API tokens

Sanctum and the package `PersonalAccessToken` model are configured only while
global Auth ingress and the API-token feature are enabled. Enable the feature
and declare the bounded ability catalog:

```php
'api_tokens' => [
    'enabled' => true,
    'routes' => ['account' => ['enabled' => true]],
    'services' => [
        'manager' => null, // built-in Sanctum manager
        'ability_provider' => null, // static settings catalog
    ],
    'settings' => [
        'abilities' => ['profile:read', 'profile:update'],
        'namespace' => 'nvl-auth',
    ],
],
```

An empty catalog denies requested abilities. The namespace isolates tokens
managed through Auth operations, even though their rows are in the dedicated
`nvl_auth_personal_access_tokens` table.

## RBAC

The package defaults to its own Spatie-compatible Role, Permission, and pivot
tables. Its built-in catalog contains every package management ability and its
templates include `super-admin`, `auth-auditor`, and `auth-user-manager`.

Applications extend, rather than replace, the catalogs with providers:

```php
'rbac' => [
    'enabled' => true,
    'services' => [
        'permission_catalogs' => [
            Nvl\Auth\Services\PackagePermissionCatalog::class,
            App\Auth\ApplicationPermissions::class,
        ],
        'role_templates' => [
            Nvl\Auth\Services\PackageRoleTemplates::class,
            App\Auth\ApplicationRoles::class,
        ],
    ],
    'settings' => [
        'guard' => 'web',
        'super_admin_role' => 'super-admin',
        'use_package_storage' => true,
    ],
],
```

Synchronization upserts declared records and assignments without deleting
unrelated records. System records can only be created by trusted PHP catalogs or
templates, never by public management request input.

## Social providers

The bundled Socialite adapter is selected when configured. Provider access and
refresh tokens are discarded. The application supplies provider client
credentials/callback policy and may replace the acquisition or subject resolver
for custom provisioning.

## Pipelines and delivery

Named pipelines are `login`, `logout`, `password_reset_requested`,
`password_reset`, `invitation_issued`, `invitation_accepted`, `client_started`,
and `api_token_issued`. Values are ordered `AuthPipelineStage` class lists.

Auth never selects a mail provider. Consume `AuthDeliveryRequested` and map its
typed request to the chosen delivery package.

## Retention

`cleanup.retention_days` controls `nvl:auth:prune`. It covers terminal or revoked
operational records only; it does not delete Users, active credentials, tokens,
RBAC state, or `nvl_auth_audits`.
