# Upgrading NVL Auth

## Major 5 consumer workflow contracts

Supported feature Actions now implement focused interfaces under
`Nvl\Auth\Contracts`, named `<Action basename without Action>Contract`.
Change host constructor type hints such as `ListApiTokensAction` to
`ListApiTokensContract` when the host needs to substitute that workflow in its
own tests. Concrete Action resolution, constructors, final/readonly qualifiers,
execute signatures, generic result types, and feature/security behavior remain
available unchanged. Follow the [host injection example](README.md#injecting-workflows-into-host-services).

New workflow defaults use `bindIf`. Existing public extension defaults now
preserve host instances and interface bindings through provider registration,
while retaining their native singleton/scoped lifetimes and lazy validation.
Re-registering Auth no longer replaces a host binding with a configured default.
To deliberately reselect a configured default, remove the old binding and its
instance before registering the provider, or explicitly install the replacement
yourself. `forgetInstance()` alone retains an existing binding. Late replacements
affect newly resolved host services; already constructed services keep their
existing dependencies. Scoped package defaults reset at the next request/job
scope, while host prebindings keep the lifetime chosen by the host.

When tenancy and memberships are enabled, Auth still supplies scoped
`AuthTenantMembershipAccess` as its neutral membership default. It preserves
real host instances, aliases, closures, singleton bindings and custom classes.
It replaces only Core's exact native, unshared string-binding fallback to the
internal `DisabledTenantMembershipAccess`, even if that transient fallback was
previously resolved. Replacement inspects the installed Laravel factory's
native closure provenance and captured target without invoking it. This narrow
compatibility check depends on Laravel's native closure metadata; unfamiliar
metadata leaves the existing binding intact. Explicitly class-binding that
internal Core disabled implementation through the same native mechanism is
treated as the package fallback; hosts should bind their supported membership
adapter instead. No host identity or tenancy configuration is adopted globally.

The five internal exclusions do not gain consumer contracts:
`AdoptPrincipalsAction`, `PruneAuthStateAction`, `IssueChallengeAction`,
`ConsumeChallengeAction`, and `ConsumeChallengeByIdAction`. Use the existing
adoption/pruning commands or the complete magic-link/security-code Actions.

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

Publish `nvl-auth-adoption` and use the staged, dry-run-first workflow in
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

Application principal subclasses may add normal host fields with a protected
`$fillable` list. The post-v1.0.3 implementation merges that list with the
configured canonical principal columns and removes duplicates. Until installing
a suite release containing this correction, a v1.0.3 host that needs extension
field mass assignment may use this compatible temporary override:

```php
public function getFillable(): array
{
    return array_values(array_unique([
        ...parent::getFillable(),
        ...$this->fillable,
    ]));
}
```

Remove the override after upgrading. Keep sensitive fields out of `$fillable`
unless the application deliberately exposes them through a validated Action.

### Self-service profile confirmation

Email changes require `currentPassword`; name-only and other nonsensitive
profile edits do not. Build a conditional request payload:

```php
[
    'name' => $name,
    'email' => $email,
    'currentPassword' => $emailChanged ? $currentPassword : null,
]
```

Missing or incorrect confirmation rejects the email change. A successful email
change clears its verification timestamp, requests a new verification delivery,
records audit facts, and emits `PrincipalChanged`.

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

## Shared Doctor integration

The loaded package provider now contributes its existing inspection checks to Core's `nvl:doctor --strict --format=json`. The package command remains available. The shared gate fails errors and, in strict mode, warnings; no data upgrade is required for diagnostics.

## Next major: isolated schema identities

This is a breaking schema identity change. Back up storage and migration history, pause writes/workers, install this code with automatic package migrations disabled, and select one owner for migrations (vendor or published).

```sh
php artisan nvl:doctor --strict --format=json
php artisan nvl:schema:upgrade --package=auth --claim-legacy --migration-owner=vendor --dry-run --format=json
php artisan nvl:schema:upgrade --package=auth --claim-legacy --migration-owner=vendor --format=json
```

The command validates released columns and relational keys plus creating migration history, renames owned legacy tables to the effective `tables.*` targets and rewrites exact package migration identities while retaining batches and unrelated host records. It refuses foreign/incomplete shapes and conflicting targets. Explicit old table mappings retain those names; remove them when choosing new defaults. A second run is empty.

Declare each published path and canonical identity explicitly in `nvl-core.migrations.published`; retimestamped history also needs an exact `legacy` mapping. Use `--migration-owner=vendor` after manually archiving declared copies outside loaded paths, or `--migration-owner=published` after manually replacing executable copies with current migration code and disabling vendor loading. The plan verifies ownership and preserves batches; checksums do not automatically claim files. Modified host copies remain host-owned. No migration files or stored morph types are rewritten.

DDL transactions are driver dependent and per connection. Inspect dry-run warnings for MySQL/MariaDB or split storage; after a failure, inspect completed steps before resuming. Schema-qualified rename targets require an explicit host schema move first. Re-enable your selected migration owner, run `nvl:schema:preflight` with the same selected paths and connection, then migrate remaining package changes and rerun Doctor before resuming writes. See the suite upgrade guide for shared owner/locale inputs, Core option defaults and one-major deprecation rules.

## Tagged consumer PHP boundary

Use source `@api` workflows, extension contracts, and value types for application integration. Direct use of untagged implementations or `@internal` members is unsupported. This classification keeps existing concrete Action signatures and runtime behavior; it does not authorize package model persistence, ad hoc queries, relation traversal, or generic model serialization. Returned models are identity/result handles with only the explicitly declared in-memory read fields described in the README.

The implementation Actions `AdoptPrincipalsAction`, `ConsumeChallengeAction`, `ConsumeChallengeByIdAction`, `IssueChallengeAction`, `PruneAuthStateAction` are explicitly internal. Use `RequestMagicLinkAction`/`ConsumeMagicLinkAction` and `RequestSecurityCodeAction`/`VerifySecurityCodeAction` for complete challenge workflows. Run `nvl:auth:adopt-principals` for reviewed adoption and `nvl:auth:prune` for retention maintenance.

The public read DTOs keep their constructors and pure value methods; `InvitationReadData`, `PermissionListItemData`, `PermissionOptionData`, `RoleListItemData`, and `RoleOptionData` model factories are internal. Use `ListInvitationProjectionsAction`, `ListRolesAction`, `ListPermissionsAction`, `ListRoleOptionsAction`, and `ListPermissionOptionsAction` with the authorized actor instead of projecting package rows yourself.
