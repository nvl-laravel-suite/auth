# Upgrading NVL Auth

## 1.0.3 from 1.0.1 or 1.0.2

### Authentication and onboarding security

Version 1.0.2 added runtime use of `nvl_auth_invitations.context_hash` and
`nvl_auth_challenges.secondary_secret_hash` but did not ship a corrective
migration for databases first installed with v1.0.1. Version 1.0.3 restores the
original v1.0.1 create migration and adds
`2026_08_12_000000_add_auth_delivery_context_columns.php` so fresh and upgraded
installations share one migration history. The migration is idempotent for
v1.0.2 fresh schemas, preserves existing rows, and intentionally leaves both new
nullable values empty for historical records.

Run migrations immediately after updating:

```bash
php artisan optimize:clear
php artisan migrate
php artisan nvl:auth:schema
php artisan nvl:auth:doctor --strict
```

Do not edit, recreate, move, or retag v1.0.2. Publish the new corrective
migration when the application uses host-owned package migrations; do not edit
an already-run published create migration.

Hosts that resolve social subjects by email must now provide verified-email
provenance. Hosts with custom login or reset admission should implement
`AuthenticationEligibility`; custom public invitation registration attributes
belong in `InvitationRegistrationMapper`.

### Feature-aware schema

Fresh migrations create only tables required by features enabled at migration
time. A 1.0.1 installation keeps any already-created dormant tables; the
upgrade does not drop them. Schema plans now report `outdated` table columns and
`missing_indexes` in addition to missing tables. Before enabling a new feature,
run:

```bash
php artisan nvl:auth:schema
php artisan nvl:auth:schema --apply
php artisan nvl:auth:doctor --strict
```

If migrations are host-owned, publish to a temporary location, copy the new
corrective migration into the host migration inventory, run `php artisan
migrate`, then use `nvl:auth:schema` to verify the result. Do not merge the new
columns into a previously executed create migration. Schema `--apply` fails
closed while `migrations.enabled=false` whenever a table, column, or index needs
repair, so it cannot bypass host ownership. Do not switch
`migrations.install_all` on in production; it exists for controlled full-schema
test and rehearsal environments.

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

RBAC-only hosts may now configure `features.rbac.models.principal` and replace
`features.rbac.services.principal_access` without enabling package principal
management. `SyncUserRolesAction` and `SyncUserPermissionsAction` now receive
`SyncUserRolesData` and `SyncUserPermissionsData`; they no longer receive raw
lists. `ApplyRoleTemplateAction` now receives `ApplyRoleTemplateData`, and
`RoleTemplateProvider::roles()` must return `RoleTemplate` values instead of a
`role => permissions` map.

Actorless bootstrap and domain transitions require a `SystemMutationContext`
with a reason and correlation identifier. They fail closed until the host
replaces `SystemMutationAccess`. Configure a custom
`PrincipalSessionContainment` when sessions exist outside Sanctum, remember
credentials, and Laravel's database session table; a replacement owns the
complete containment contract.

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
