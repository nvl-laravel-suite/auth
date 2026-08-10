# Upgrading NVL Auth

## Unreleased from 1.0.1

### Authentication and onboarding security

Run migrations after updating. Existing installations gain nullable
`nvl_auth_invitations.context_hash` and
`nvl_auth_challenges.secondary_secret_hash` columns. Publish the new corrective
migration when the application publishes package migrations; do not edit an
already-run published migration.

Hosts that resolve social subjects by email must now provide verified-email
provenance. Hosts with custom login or reset admission should implement
`AuthenticationEligibility`; custom public invitation registration attributes
belong in `InvitationRegistrationMapper`.

### Feature-aware schema

Fresh migrations now create only tables required by features enabled at
migration time. A 1.0.1 installation keeps any already-created dormant tables;
the upgrade does not drop them. Before enabling a new feature, run:

```bash
php artisan nvl:auth:schema
php artisan nvl:auth:schema --apply
php artisan nvl:auth:doctor --strict
```

If migrations are host-owned, republish to a temporary location, merge the new
idempotent feature guards into the maintained host copies, run `php artisan
migrate`, then use `nvl:auth:schema` to verify the result. Schema `--apply` fails
closed while `migrations.enabled=false` so it cannot bypass host ownership. Do
not switch `migrations.install_all` on in production; it exists for controlled
full-schema test and rehearsal environments.

### Existing first-party Users

Publish `auth-adoption` and use the staged, dry-run-first workflow in
[principal adoption](docs/principal-adoption.md). The versioned manifest maps
legacy principal columns, extension columns, password-reset tokens, and
application foreign keys. IDs must remain UUIDs. Password and reset-token hashes
are preserved rather than rehashed.

Do not drop source tables on the first run. Reconcile counts, authentication,
password reset, domain relationships, and Doctor output before changing
`drop_sources` to true.

### Custom principal models

Publish the new configuration and preserve the complete
`features.principal_management.settings.attributes` map. Map package semantics
to physical host columns, including namespaced metadata columns when the model
has relationships such as `profile()`. Doctor now fails when any physical
principal column shadows a declared Eloquent relationship.

## Package-owned identity release

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
