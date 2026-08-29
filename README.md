# NVL Auth — API and usage

[← NVL Laravel Suite](../../../README.md)

## Quick reference

| Item | Value |
|---|---|
| Installed through | `composer require nvl/laravel-suite:^1.0` |
| Module identifier | `nvl/auth` |
| PHP namespace | `Nvl\Auth` |
| Service provider | `Nvl\Auth\Providers\AuthServiceProvider` |
| Configuration | `config/nvl-auth.php` |

## Purpose

NVL Auth is a reusable Laravel authentication platform with an optional,
versioned JSON API. It works out of the box with a concrete UUID User model,
password authentication, profiles, user administration, Spatie Permission,
Sanctum tokens, invitations, passkeys, and security audit facts. Every model,
Action, Service, route family, and adapter remains replaceable or extensible.

It contains no Inertia pages and sends no mail. Message-producing use cases
dispatch a typed, after-commit `AuthDeliveryRequested` event. Applications may
consume that event with `nvl/mail-notifications`, Laravel Notifications, SMS,
push, or another transport without coupling Auth to delivery infrastructure.

## Installation

```bash
composer require nvl/laravel-suite:^1.0
php artisan vendor:publish --tag=auth-config
php artisan vendor:publish --tag=auth-skills
php artisan vendor:publish --tag=auth-adoption
php artisan migrate
php artisan nvl:auth:schema
php artisan nvl:auth:doctor
```

Package discovery registers the root Suite provider, which selects
`AuthServiceProvider` through `config/nvl-suite.php`. With the default
configuration NVL Auth supplies the application's authentication User model,
password-reset repository, Spatie Role and Permission models, and Sanctum
PersonalAccessToken model. Routes remain off until explicitly enabled. When
global Auth ingress is disabled, provider registration is passive and does not
replace host Auth, Permission, Sanctum, or migration state.

### Migration ownership modes

Choose exactly one migration owner:

1. **Automatic vendor loading (default):** leave `nvl-auth.migrations.enabled=true`, do not publish `auth-migrations`, and run `php artisan migrate`.
2. **Host-owned published migrations:** publish `auth-migrations`, set `nvl-auth.migrations.enabled=false` before migrating, and maintain the published files as application migrations.

   ```bash
   php artisan vendor:publish --tag=auth-migrations
   ```

Never run both sources. Laravel retimestamps files published through the migration tag. `php artisan nvl:auth:doctor` reports a warning when automatic loading remains enabled and `database/migrations` contains a timestamp-independent name matching a package migration; `--strict` promotes that warning to failure.

Migrations create only the tables required by features enabled at migration
time. Before enabling another feature in an existing installation, deploy its
configuration, run `php artisan nvl:auth:schema`, review the missing-table plan,
then run `php artisan nvl:auth:schema --apply`. The apply command reuses the
idempotent package migrations and verifies that every required table exists.

## Ownership

| Concern | Authority |
|---|---|
| User identity, profile, lifecycle, search, bulk operations | NVL Auth |
| Password authentication and reset-token persistence | NVL Auth using Laravel guard/broker contracts |
| Roles, permissions, hierarchy, templates, analytics, pivots | NVL Auth using Spatie Permission behavior |
| Personal access tokens | NVL Auth using Sanctum behavior |
| Invitations, challenges, authenticators, clients, social links, audits | NVL Auth |
| Browser session runtime and cookies | Laravel |
| Application-specific User relationships and business policy | consumer extension/pipelines |
| Mail, SMS, push, templates, transport retries | event consumer such as `nvl/mail-notifications` |

The default `Nvl\Auth\Models\User` is a complete authenticatable model. A
consumer that needs application relationships subclasses it and changes only
`features.principal_management.models.user`; package Actions and routes continue
to operate on the configured class. Host schemas may map every package principal
attribute to a different physical column through
`features.principal_management.settings.attributes`.

### Embedded applications and host policies

Applications that own their pages and HTTP controllers can preview a focused
overlay instead of publishing the full package configuration:

```bash
php artisan nvl:auth:configure \
    --preset=embedded-application \
    --user-model='App\Models\User'
```

The command is a dry run by default. Add `--write` to create a missing file. To
replace an existing file, first run the dry run with the intended options and
review its unified diff, then repeat it with `--write --force`. Repeatable
`--enable` and `--disable` options add only explicit feature overrides. The
preset keeps package HTTP routes off, marks HTTP and delivery as host-owned,
configures the host User model, and selects the policy adapter.

The adapter removes the need to define one Laravel Gate for every
`nvl-auth.*` ability. Map closed package aliases to methods on registered Laravel
policies instead:

```php
use App\Models\User;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

'management' => [
    'abilities' => [
        'users.viewAny' => 'viewAny',
        'users.view' => 'view',
        'users.create' => 'create',
        'users.update' => 'update',
        'rbac.view' => 'viewRbac',
        'rbac.manageRoles' => 'manageRoles',
        'rbac.managePermissions' => 'managePermissions',
        'rbac.synchronize' => 'synchronizeRbac',
    ],
    'policy_models' => [
        'users' => User::class,
        'roles' => Role::class,
        'permissions' => Permission::class,
    ],
],
```

Register those model policies through Laravel's normal policy discovery or
`Gate::policy`. Unknown aliases, missing mappings, invalid model classes, and
wrong target types deny access. A custom `AuthManagementAccess` implementation
remains the supported escape hatch for domain authorization that cannot be
expressed as model-policy decisions.

Use `php artisan nvl:auth:configuration --format=json` to inspect effective
features, route ownership, model classes, adapters, policy coverage, and Suite
configuration drift without printing configuration values or secrets. Run
`php artisan nvl:auth:doctor --strict` after registering host routes and policies.

## Features

Every capability has `features.<name>.enabled` and per-surface route switches.
Direct PHP Actions and HTTP middleware use the same fail-closed `FeatureGate`.

| Feature | Default | Capability |
|---|---:|---|
| `authentication` | on | guarded login/logout and passwordless session establishment |
| `principal_management` | on | User CRUD, restore, active status, bulk operations, profile, search, suggestions, role/permission assignment |
| `password` | on | password confirmation/update and broker reset flows |
| `email_verification` | off | signed verification lifecycle and delivery payload |
| `magic_links` | off | expiring, hashed, one-time magic links |
| `security_codes` | off | bounded-attempt numeric verification codes |
| `invitations` | off | issue, resend, preview, accept, revoke, expire, optional RBAC assignment |
| `totp` | off | enrollment, verification, replay protection, revocation |
| `passkeys` | off | built-in WebAuthn registration/authentication and credential management |
| `recovery_codes` | off | one-time recovery-code batches |
| `social_identities` | off | Socialite or custom OAuth identity acquisition/linking |
| `clients` | off | first-party client allowlists and Laravel-session correlation |
| `sessions` | on | admission around Laravel browser-session operations |
| `api_tokens` | off | Sanctum token issue/list/update/rotate/revoke with bounded abilities |
| `rbac` | on | package Role/Permission CRUD, hierarchy, cloning, templates, analytics, synchronization |
| `audit` | on | bounded queryable authentication audit facts |

Disabling a feature removes its routes and blocks its normal Actions; it never
deletes persisted data. Containment operations such as revoke and cleanup remain
available where classified.

## Enabling the API

All HTTP surfaces are deliberately opt-in. For example, to enable profile and
user/RBAC management routes:

```php
'routes' => [
    'enabled' => true,
    'prefix' => 'api/v1/auth',
    'middleware' => ['api'],
    'account' => [
        'enabled' => true,
        'middleware' => ['auth:sanctum', 'throttle:nvl-auth-account'],
    ],
    'management' => [
        'enabled' => true,
        'middleware' => ['auth:sanctum', 'throttle:nvl-auth-management'],
    ],
],

'features' => [
    'principal_management' => [
        'enabled' => true,
        'routes' => [
            'account' => ['enabled' => true],
            'management' => ['enabled' => true],
        ],
    ],
    'rbac' => [
        'enabled' => true,
        'routes' => ['management' => ['enabled' => true]],
    ],
],
```

A route is registered only when global routing, its surface, its feature route
switch, the feature, and its dependencies are enabled. Feature middleware
rechecks admission so stale route caches fail with `404 feature_unavailable`.
After configuration deployment rebuild config/route caches and restart workers.

## Models and extension

The default concrete models are:

- `Nvl\Auth\Models\User`
- `Nvl\Auth\Models\Role`
- `Nvl\Auth\Models\Permission`
- `Nvl\Auth\Models\PersonalAccessToken`

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Nvl\Auth\Models\User as AuthUser;

final class User extends AuthUser
{
    /** @var list<string> */
    protected $fillable = [
        'phone',
        'organization_id',
        'position',
    ];

    public function orders(): HasMany
    {
        return $this->hasMany(Order::class);
    }
}
```

Configured canonical principal columns are always mass assignable. The package
merges them with this subclass list, removes duplicates, and keeps every
unlisted host attribute protected. Extension fields therefore survive `fill()`,
`create()`, and `update()` without weakening mass-assignment protection.

```php
'features' => [
    'principal_management' => [
        'models' => ['user' => App\Models\User::class],
    ],
],
```

Use named pipelines for application policy around login, logout, password reset,
invitations, clients, and API-token issue. Replace contract bindings only where
the application needs different identity, authorization, social, passkey, token,
or audit behavior.

Authentication admission is independently replaceable through
`features.authentication.services.eligibility`; every session-establishment and
password-reset path uses it. Sensitive self-service mutations use
`features.principal_management.services.account_confirmation`. Invitation hosts
can replace `features.invitations.services.registration_mapper` to map validated
registration extensions to their configured principal model.

Self-service profile updates require the current password only when a sensitive
field changes, especially email. Submit conditional payloads rather than asking
for a password on name-only edits:

```php
[
    'name' => $name,
    'email' => $email,
    'currentPassword' => $emailChanged ? $currentPassword : null,
]
```

An email change with missing or incorrect confirmation fails closed. A
successful change clears `email_verified_at`, requests a fresh verification
delivery, records the audit facts, and dispatches `PrincipalChanged`.

RBAC assignment is independently configurable through
`features.rbac.models.principal` and
`features.rbac.services.principal_access`, so a host can use package roles and
permissions without enabling package-shaped principal CRUD. Actorless bootstrap
or domain transitions require a traceable `SystemMutationContext` and an
explicit host `SystemMutationAccess` grant. Destructive lifecycle Actions invoke
the replaceable `PrincipalSessionContainment` contract for API tokens, remember
credentials, Laravel database sessions, and host extensions.

## RBAC consumer reads and analytics

Use RBAC Actions for option lists, suggestions, catalogs, name availability,
mixed ID/name resolution, assignments, and analytics. Consumers must not start
queries from `Role` or `Permission`; the Actions own feature admission,
authorization, configured models and guards, input bounds, and portable query
semantics.

Per-role analytics is an identity-free projection. It counts principals using
the configured active-column mapping, aggregates canonical permission groups,
and traverses the role hierarchy with a bounded number of queries. Activity is
intentionally a separate package concern and can be composed from the identity
returned by `ShowRoleAction`:

```php
use Nvl\Activity\Services\ActivityReadService;
use Nvl\Auth\Actions\Rbac\ShowRoleAction;
use Nvl\Auth\Actions\Rbac\ShowRoleAnalyticsAction;

$role = app(ShowRoleAction::class)->execute($actor, $roleId);
$analytics = app(ShowRoleAnalyticsAction::class)->execute($actor, $roleId);
$activity = app(ActivityReadService::class)->paginateForSubjectKey(
    $role->getMorphClass(),
    $role->getKey(),
    20,
);
```

The Action-returned role may be used only as the authorized identity/result for
that composition. A consumer-initiated role query is still outside the public
application boundary.

## Passkeys and tokens

Passkeys work without a host ceremony class. Enable the feature and configure a
valid relying-party ID and HTTPS origin allowlist. The included maintained
WebAuthn adapter handles option creation and cryptographic verification; a
custom `PasskeyCeremony` remains supported.

Sanctum is a runtime dependency. The default token manager and package-owned
`nvl_auth_personal_access_tokens` table are ready when `api_tokens` is enabled.
Configure the allowed ability catalog before issuance; the empty default denies
all requested abilities.

## Delivery events

```php
use Nvl\Auth\Events\AuthDeliveryRequested;

final class DeliverAuthMessage
{
    public function handle(AuthDeliveryRequested $event): void
    {
        $request = $event->request;

        // Render from $request->subject or $request->invitation when present,
        // then deliver the secret-bearing $request->payload.
    }
}
```

Each delivery feature owns exactly one message type. Magic-link delivery
includes `challenge_id`, an opaque `secret`, and a numeric `code`; either
credential atomically consumes the same challenge. Its request also carries the
challenged `SubjectReference`. Invitation delivery carries a bounded
`InvitationDeliveryData` projection with recipient, purpose, inviter, grants,
expiry, resend count, and only metadata keys explicitly allowlisted by
`features.invitations.settings.delivery_metadata_keys`.

Auth owns the message intent and secure payload. The consumer owns channel,
template, provider, delivery retry, and provider callback concerns. The request
`messageId` is the stable idempotency and outcome-correlation key.

Successful direct and registration-through-invitation acceptance dispatches an
after-commit `InvitationAccepted` event exactly once. It contains only the
invitation ID, type, purpose, accepted `SubjectReference`, and durable
`acceptedAt` timestamp; bearer tokens, recipient addresses, and invitation
metadata are deliberately excluded.

## Consumer application APIs

Application code should enter Auth through Actions and consume DTOs. The main
read boundaries are the [RBAC consumer reads](#rbac-consumer-reads-and-analytics)
and the [invitation consumer reads](#invitation-consumer-reads-and-delivery-outcomes)
below. Package model reads remain a documented 1.x compatibility surface, not
the preferred boundary for new applications.

## Invitation consumer reads and delivery outcomes

Use `ListInvitationProjectionsAction` for authorized management lists. It
accepts `InvitationIndexQueryData`, including bounded `types`, lifecycle,
recipient, purpose, context, and expiry filters, and returns a paginator of
`InvitationReadData`. The DTO contains only usable consumer state; token,
recipient, context, and active-key hashes plus the current delivery message ID
are never exposed.

```php
use Nvl\Auth\Actions\Invitations\ListInvitationProjectionsAction;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;

$invitations = app(ListInvitationProjectionsAction::class)->execute(
    $actor,
    new InvitationIndexQueryData(
        types: ['candidate', 'registration'],
        lifecycle: 'active',
        context: $campaignId,
    ),
);
```

`FindActiveInvitationAction` performs normalized exact recipient, purpose,
optional type, and hashed-context lookup without exposing the model. Pass a
management actor whenever one exists. Actorless lookup is a trusted server-only
boundary and requires an explicitly constructed
`InvitationIssuanceContext(actorlessAuthorized: true)`; never hydrate that
context from public request data.

Resend and revoke workflows may pass an invitation ID directly to
`ResendInvitationAction` and `RevokeInvitationAction`. The Actions resolve and
lock the authoritative row before authorization and mutation.

After an invitation transport attempt, report only a coarse result through
`RecordInvitationDeliveryOutcomeAction`: `Delivered`, or `Failed` with a stable
safe failure code such as `provider_rejected`. Never pass provider exception
messages. Auth ignores stale callbacks for superseded resend message IDs,
records that fact in its audit stream, and makes duplicate callbacks
idempotent. Provider IDs, raw responses, retry scheduling, and detailed delivery
telemetry remain host-owned.

## Storage

Package migrations install only schema owned by features enabled at migration
time. A globally disabled provider does not load migrations unless
`migrations.load_when_disabled=true` is explicitly set. Across all features the
inventory contains 17 UUID-first, `nvl_auth_`-prefixed tables: User, RBAC and
pivots, Sanctum tokens, password resets, clients/session correlations,
invitations, challenges, TOTP, passkeys, recovery codes, social identities, and
audits. It intentionally contains no mail delivery, notification, queue,
outbox, workflow, or maintenance-checkpoint tables.

See [schema](docs/schema.md) for the exact inventory.

## Operations

```bash
php artisan nvl:auth:features
php artisan nvl:auth:features --format=json
php artisan nvl:auth:configure --preset=embedded-application --user-model='App\Models\User'
php artisan nvl:auth:configuration --format=json
php artisan nvl:auth:schema
php artisan nvl:auth:schema --apply
php artisan nvl:auth:doctor --strict
php artisan nvl:auth:prune --dry-run
php artisan nvl:auth:prune
```

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Feature manifest](docs/feature-manifest.md)
- [PHP API](docs/php-api.md)
- [HTTP API](docs/http-api.md)
- [Delivery events](docs/delivery.md)
- [Extending](docs/extending.md)
- [Principal adoption](docs/principal-adoption.md)
- [Operations](docs/operations.md)
- [Schema](docs/schema.md)
- [Security](docs/security.md)
- [Upgrade guide](UPGRADING.md)

## Verification

```bash
vendor/bin/pest --configuration=packages/nvl/auth/phpunit.xml.dist packages/nvl/auth/tests
vendor/bin/phpstan analyse --configuration=packages/nvl/auth/phpstan.neon.dist
vendor/bin/pint --format agent packages/nvl/auth
```

## License

NVL Auth is released under the MIT License. See [LICENSE](LICENSE).
