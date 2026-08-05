# Upgrading to the package-owned identity release

This pre-1.0 release intentionally replaces the prior host-owned identity/RBAC
layout. There is no runtime compatibility shim.

## Configuration

Every feature is an object with a hard `enabled` boolean, nested routes,
services/models, and settings:

```php
'features' => [
    'principal_management' => [
        'enabled' => true,
        'routes' => [
            'account' => ['enabled' => false],
            'management' => ['enabled' => false],
        ],
        'models' => ['user' => Nvl\Auth\Models\User::class],
    ],
],
```

Old scalar modes map to `enabled=false` for `off`, or `enabled=true` for every
active mode. Put finer application lifecycle policy in pipelines. Routes remain
off until global, surface, and feature route switches are explicitly enabled.

## Schema ownership

The default schema now owns these identity/provider tables in addition to the
nine existing Auth mechanism tables:

- `nvl_auth_users`;
- `nvl_auth_permissions` and `nvl_auth_roles`;
- `nvl_auth_model_has_permissions`, `nvl_auth_model_has_roles`, and
  `nvl_auth_role_has_permissions`;
- `nvl_auth_personal_access_tokens`;
- `nvl_auth_password_reset_tokens`.

All nine former unprefixed mechanism tables are now prefixed `nvl_auth_` as
listed in [docs/schema.md](docs/schema.md). Existing data is not automatically
copied. Back it up and write an application-specific migration that preserves
UUIDs, morph aliases, hashes, ciphertext, timestamps, and foreign keys before
dropping old tables.

## Users, RBAC, and tokens

The package User is the default Laravel auth-provider model. Move identity,
profile, status, and login state into `nvl_auth_users`. When the application
needs cross-module relationships, subclass the package User and configure the
subclass; do not copy package Actions/controllers into an application module.

Move Spatie role/permission data and UUID pivots into the namespaced package
tables. Move only the Sanctum tokens that Auth should own into
`nvl_auth_personal_access_tokens`; preserve token hashes and morph identity. The
package token namespace continues to bound list/update/rotate/revoke operations.

## Delivery

Replace Auth mail/notification implementations with an
`AuthDeliveryRequested` listener. Auth does not create transport/delivery tables
or send messages directly. A delivery package owns templates, channels, retries,
and provider callbacks.

## Deployment

```bash
php artisan optimize:clear
php artisan migrate
php artisan config:cache
php artisan route:cache
php artisan queue:restart
php artisan nvl:auth:doctor --strict
```

Do not change the operational connection or remove old encryption/hash keys
until every retained row has been migrated and verified.
