# NVL Auth — API and usage

## Quickstart

```sh
composer require nvl/auth:^5.0
php artisan nvl:install auth --dry-run
php artisan nvl:install auth
```

Required NVL dependencies: `nvl/core` (`^5.0`). Select Auth features deliberately and bind host identity/management policies. Installing the package does not adopt your existing auth guards or user model.
Review the published common config, select one migration owner, and run schema preflight before existing-table upgrades. The installer does not enable features or run migrations. Follow the detailed installation and capability sections below before invoking a storage/provider operation.

Inject `Nvl\Auth\Contracts\ListUsersContract` in a host service. After supplying the trusted inputs described above, the first public call is:

```php
use Nvl\Auth\Contracts\ListUsersContract;

/** @var ListUsersContract $capability */
$result = $capability->execute($actor);
```

Use the [event catalog](docs/events.md) and [Testing your app](#testing-your-app) below. The suite [getting-started guide](https://github.com/nvl-laravel-suite/laravel-suite/blob/main/docs/getting-started.md) provides a complete Comments host fixture; package archives retain their own local references.


[← NVL Laravel Suite](https://github.com/nvl-laravel-suite)

For support, [open an issue](https://github.com/nvl-laravel-suite/auth/issues). For vulnerabilities, use
[private reporting](https://github.com/nvl-laravel-suite/auth/security/advisories/new). See [Contributing](CONTRIBUTING.md).

See the [installation and publishing guide](https://github.com/nvl-laravel-suite/laravel-suite/blob/main/docs/installation.md) for Composer setup, configuration, migration ownership, and agent skills.

Principal adoption (`nvl-auth.adoption.principal_model.enabled` with explicit `guard` and `provider`), password-broker storage (`adoption.password_broker.enabled` with explicit `broker`), and Spatie storage (`adoption.spatie_storage.enabled`) are independent and default to `false`. Installation preserves the complete host `auth` and `permission` configuration, including team scoping. Auth HTTP routes remain disabled until explicitly enabled. Adopted permission storage initializes lazily, fails closed when unavailable, and memoizes readiness per request/job; restart workers after changing adoption or tenancy configuration. Doctor reports each adopted target and effective storage.

For a fresh installation, run the owned migrations before enabling Spatie storage adoption, then rebuild config and restart workers. Spatie's provider-boot registrar wiring does not probe tables; resolving permission services after boot requires the adopted storage to be ready, including when Artisan discovers permission commands.

## Quick reference

| Item | Value |
|---|---|
| Installed through | `composer require nvl/auth:^5.0` |
| Module identifier | `nvl/auth` |
| PHP namespace | `Nvl\Auth` |
| Service provider | `Nvl\Auth\Providers\AuthServiceProvider` |
| Configuration | `config/nvl-auth.php` |

## Purpose

NVL Auth is a reusable Laravel authentication platform with an optional,
versioned JSON API. It works out of the box with a concrete UUID User model,
password authentication, profiles, user administration, Spatie Permission,
Sanctum tokens, invitations, passkeys, and security audit facts. Each
supported workflow retains its concrete Action and exposes a focused contract
for host substitution; models and adapters keep their documented extension seams.

It contains no Inertia pages and sends no mail. Message-producing use cases
dispatch a typed, after-commit `AuthDeliveryRequested` event. Applications may
consume that event with `nvl/mail-notifications`, Laravel Notifications, SMS,
push, or another transport without coupling Auth to delivery infrastructure.

## Injecting workflows into host services

Inject `Nvl\Auth\Contracts\<Action name without Action>Contract` for supported
feature workflows. For example, `ListApiTokensContract`,
`ListInvitationProjectionsContract`, and `LogoutContract` expose the existing
Actions' exact `execute()` parameters, defaults, sensitive-parameter attributes,
and result/PHPDoc types. The invitation contract retains its DTO paginator;
token listing retains `list<ApiTokenSnapshot>` and logout retains `void`.

```php
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ListApiTokensContract;
use Nvl\Auth\Contracts\LogoutContract;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

final readonly class HostAccountScreen
{
    public function __construct(
        private ListApiTokensContract $tokens,
        private LogoutContract $logout,
    ) {}

    /** @return list<string> */
    public function tokenNames(Authenticatable $subject): array
    {
        return array_map(
            static fn (ApiTokenSnapshot $token): string => $token->name,
            $this->tokens->execute($subject),
        );
    }

    public function signOut(): string
    {
        $this->logout->execute();

        return '/signed-out';
    }
}
```

In a host test, substitute the interface with a native Mockery mock or an
anonymous implementation, then resolve and invoke the real host service:

```php
use Carbon\CarbonImmutable;
use Nvl\Auth\Contracts\ListApiTokensContract;
use Nvl\Auth\Contracts\LogoutContract;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

$subject = User::factory()->make();
$tokens = Mockery::mock(ListApiTokensContract::class);
$tokens->shouldReceive('execute')->once()->with($subject)->andReturn([
    new ApiTokenSnapshot('token-42', 'Host dashboard', ['profile:read'], null, null, CarbonImmutable::now()),
]);
$logout = Mockery::mock(LogoutContract::class);
$logout->shouldReceive('execute')->once()->withNoArgs()->andReturnNull();
$this->app->instance(ListApiTokensContract::class, $tokens);
$this->app->instance(LogoutContract::class, $logout);
$screen = $this->app->make(HostAccountScreen::class);

expect($screen->tokenNames($subject))->toBe(['Host dashboard']);
expect($screen->signOut())->toBe('/signed-out');
```

Focused defaults use transient `bindIf` registrations. Host prebindings remain
authoritative through provider registration; a later `instance()` replacement
reaches newly resolved host services. Existing final/readonly Actions remain
directly resolvable with their original constructors. Existing feature extension
contracts keep their native singleton/scoped lifetimes and lazy configuration
validation, with conditional defaults. Internal Action chains retain their
own concrete dependencies. Host substitution tests isolate application
orchestration; retain package integration tests for authorization, storage,
session security, and delivery behavior.

`AdoptPrincipalsAction`, `PruneAuthStateAction`, and
`Challenges\{IssueChallenge,ConsumeChallenge,ConsumeChallengeById}Action` are
internal command/helper implementations. Use the documented operational commands
or complete magic-link/security-code workflows. See [UPGRADING.md](UPGRADING.md)
for binding precedence and the bounded Core membership fallback exception.

## Installation

For a clean application, review the Auth configuration before running migrations:

```bash
composer require nvl/auth:^5.0
php artisan vendor:publish --tag=nvl-auth-translations
php artisan vendor:publish --tag=nvl-auth-config
php artisan migrate
php artisan nvl:auth:schema
php artisan nvl:auth:doctor
```

Publish the bundled guidance only if the application's agents need it:

```bash
php artisan vendor:publish --tag=nvl-auth-skills
```

For an existing identity schema, follow the
[principal adoption guide](docs/principal-adoption.md) before publishing its
principal-adoption manifest with `php artisan vendor:publish --tag=nvl-auth-adoption`.
This tag is not part of a clean installation.

Laravel package discovery registers `AuthServiceProvider` directly. With the
default `config/nvl-auth.php` settings, NVL Auth supplies the application's authentication User model,
password-reset repository, Spatie Role and Permission models, and Sanctum
PersonalAccessToken model. Routes remain off until explicitly enabled. When
global Auth ingress is disabled, provider registration is passive and does not
replace host Auth, Permission, Sanctum, or migration state.

### Migration ownership modes

Choose exactly one migration owner:

1. **Automatic vendor loading (default):** leave `nvl-auth.migrations.enabled=true`, do not publish `nvl-auth-migrations`, and run `php artisan migrate`.
2. **Host-owned published migrations:** publish `nvl-auth-migrations`, set `nvl-auth.migrations.enabled=false` before migrating, and maintain the published files as application migrations.

   ```bash
   php artisan vendor:publish --tag=nvl-auth-migrations
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
    'prefix' => 'nvl/api/v1/auth',
    'middleware' => ['api'],
    'account' => [
        'enabled' => true,
        'middleware' => ['auth:sanctum', 'throttle:nvl.auth.account'],
    ],
    'management' => [
        'enabled' => true,
        'middleware' => ['auth:sanctum', 'throttle:nvl.auth.management'],
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
below. Package models provide identity handles and only explicitly declared
in-memory fields; consumer queries and writes use the supported Actions.

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

Tenant ownership is opt-in through `nvl-tenancy.enabled`. Existing installations
must use the reviewed `nvl:tenancy:adopt` workflow; `nvl:auth:schema --apply`
never guesses owners or activates tenant storage. Adoption creates explicit
memberships, clones reviewed roles per tenant, revokes package-managed unbound
tokens, classifies historical rows, and only then activates Spatie team mode.
Restart queue workers after activation. In tenant mode pruning requires exactly
one of `--tenant=<uuid>` or an authorized `--platform` operation.

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

From a standalone checkout of the public Auth repository:

```bash
composer install
composer quality
```

## Supported PHP usage

The source `@api` declarations identify supported workflows, extension contracts, and value types. Public members marked `@internal` and untagged implementation types remain package-owned. Concrete Actions retain their existing constructors, qualifiers, and `execute()` signatures.

A package model returned or accepted by a public workflow is an identity/result handle. Use its declared type and `getKey()`, `getKeyName()`, `getMorphClass()`, `getRouteKey()`, `getRouteKeyName()`, `is()`, `isNot()`, and `relationLoaded()`. Read only explicitly declared in-memory `@nvl-consumer-read` fields; ordinary model PHPDocs and fillable attributes do not grant consumer reads. Obtain display projections through public reads. Persistence, additional model queries, relation access/loading, and generic model serialization are outside this contract. Host-model queries remain available, while traversal or aggregates of package capability relations require the package public reader or authorized adapter.

## Shared consumer diagnostics

Run `php artisan nvl:doctor --strict --format=json` to combine the read-only checks from loaded NVL package providers. Errors fail the gate, and strict mode also fails warnings. This package's existing Doctor command remains available and uses the same package-owned inspection service.

## Next major: isolated schema identities

Use `nvl-auth.tables.<logical-key>` for every table and `nvl-auth.connection` for its database connection. Null connection inherits `nvl-core.connection`, then Laravel's default. Tables are resolved at runtime by the package table definition helper.

| Logical key | New default | Previous name |
| --- | --- | --- |
| `users` | `nvl_auth_users` | `nvl_auth_users` |
| `roles` | `nvl_auth_roles` | `nvl_auth_roles` |
| `permissions` | `nvl_auth_permissions` | `nvl_auth_permissions` |
| `model_has_permissions` | `nvl_auth_model_has_permissions` | `nvl_auth_model_has_permissions` |
| `model_has_roles` | `nvl_auth_model_has_roles` | `nvl_auth_model_has_roles` |
| `role_has_permissions` | `nvl_auth_role_has_permissions` | `nvl_auth_role_has_permissions` |
| `personal_access_tokens` | `nvl_auth_personal_access_tokens` | `nvl_auth_personal_access_tokens` |
| `password_reset_tokens` | `nvl_auth_password_reset_tokens` | `nvl_auth_password_reset_tokens` |
| `clients` | `nvl_auth_clients` | `nvl_auth_clients` |
| `client_sessions` | `nvl_auth_client_sessions` | `nvl_auth_client_sessions` |
| `invitations` | `nvl_auth_invitations` | `nvl_auth_invitations` |
| `challenges` | `nvl_auth_challenges` | `nvl_auth_challenges` |
| `totp_credentials` | `nvl_auth_totp_credentials` | `nvl_auth_totp_credentials` |
| `passkeys` | `nvl_auth_passkeys` | `nvl_auth_passkeys` |
| `recovery_codes` | `nvl_auth_recovery_codes` | `nvl_auth_recovery_codes` |
| `social_identities` | `nvl_auth_social_identities` | `nvl_auth_social_identities` |
| `audits` | `nvl_auth_audits` | `nvl_auth_audits` |
| `tenant_memberships` | `nvl_auth_tenant_memberships` | `nvl_auth_tenant_memberships` |
| `tenant_membership_locks` | `nvl_auth_tenant_membership_locks` | `nvl_auth_tenant_membership_locks` |
| `tenant_authentication_intents` | `nvl_auth_tenant_authentication_intents` | `nvl_auth_tenant_authentication_intents` |

Migration filenames contain `nvl_auth_`. Existing installations must complete the upgrade in `UPGRADING.md` before running new migrations. A pending creator rejects an existing target before that owned migration runs; use `nvl:schema:preflight` for an explicit whole-batch check; legacy storage with old history needs an ownership decision.

## Canonical configuration ownership

Use `nvl-auth` settings in `config/nvl-auth.php` and canonical package environment names. Old generic roots are foreign unless an upgrading NVL host explicitly selects them in Core's default-off compatibility. Canonical false/null/empty values win; no old roots are populated or written back. Keep logical package/resource IDs unchanged. Review [Core's rename inventory and cache/worker cutover](https://github.com/nvl-laravel-suite/core/blob/main/UPGRADING.md#major-5-canonical-configuration-and-environment).

## Testing your app

Inject the supported contract rather than constructing its concrete Action or querying package tables. Replace `Nvl\Auth\Contracts\ListUsersContract` in Laravel's native container for a host-workflow test:

```php
use Nvl\Auth\Contracts\ListUsersContract;

$double = Mockery::mock(ListUsersContract::class);
$this->app->instance(ListUsersContract::class, $double);
// Configure the exact execute arguments and documented return value for your host case.
```

The package's conditional native binding preserves host substitutions. Production uses the real contract; test doubles do not prove its storage/authorization behavior.

A detached fixture for a returned identity/data handle is:

```php
use Nvl\Auth\Models\User;
$fixture = User::factory()->withoutParents()->make();
```

Ordinary `make()` may persist declared package parents. `withoutParents()->make()` disables parent expansion/admission for detached fixtures; use explicit persisted parents/owners and matching effective connections for a real `create()`. Factories do not authorize workflows, call Stripe, create backing Media objects or publish Template artifacts. Enabled tenancy requires explicit admitted persisted tenants/parents. Your host test installation supplies Faker; no test runner is a runtime package dependency.

Use Laravel `Event::fake()`, `Queue::fake()`, `Mail::fake()` or `Storage::fake()` only for the effects the host test intends to isolate. Use real commits/listeners for timing proof. Add the optional Core consumer boundary rules to host PHPStan:

```neon
includes:
    - vendor/nvl/core/support/consumer-audit.neon
parameters:
    nvlConsumer:
        testPaths: [tests]
        tableNames: []
        exceptions: []
```

Rules read installed public metadata without suite boot. They flag internal symbols, package model queries/writes, capability relations and owned tables; they cannot prove dynamic code or runtime authorization. Exact exceptions require `file`, `identifier`, `symbol`, and a documented `reason`. New C3/C4/E tests, archives and guide execution remain pending until the integration phase records results.

### Shipped factory states

These runtime builders keep Laravel's native Factory API. The listed methods name explicit supported parent/owner/lifecycle states; follow each factory's native admission requirements. Detached examples above do not assert persistence validity.

| Factory | Explicit states |
| --- | --- |
| [`AuthAuditFactory`](database/factories/AuthAuditFactory.php) | Native Factory states only |
| [`AuthClientFactory`](database/factories/AuthClientFactory.php) | Native Factory states only |
| [`AuthClientSessionFactory`](database/factories/AuthClientSessionFactory.php) | Native Factory states only |
| [`ChallengeFactory`](database/factories/ChallengeFactory.php) | Native Factory states only |
| [`InvitationFactory`](database/factories/InvitationFactory.php) | Native Factory states only |
| [`PasskeyFactory`](database/factories/PasskeyFactory.php) | `forSubject(User $subject)` |
| [`PermissionFactory`](database/factories/PermissionFactory.php) | Native Factory states only |
| [`PersonalAccessTokenFactory`](database/factories/PersonalAccessTokenFactory.php) | Native Factory states only |
| [`RecoveryCodeFactory`](database/factories/RecoveryCodeFactory.php) | `forSubject(User $subject)` |
| [`RoleFactory`](database/factories/RoleFactory.php) | Native Factory states only |
| [`SocialIdentityFactory`](database/factories/SocialIdentityFactory.php) | `forSubject(User $subject)` |
| [`TenantMembershipFactory`](database/factories/TenantMembershipFactory.php) | `forTenant(TenantId $tenant)`, `forSubject(User $subject)` |
| [`TotpCredentialFactory`](database/factories/TotpCredentialFactory.php) | `forSubject(User $subject)` |
| [`UserFactory`](database/factories/UserFactory.php) | `unverified()`, `disabled()` |

## Error codes and events

All recognized package failures implement `Nvl\Support\Contracts\PackageException`; only `RespondableException` opts into safe response metadata. Keep native PHP programmer errors and Laravel/SDK exceptions distinct. The optional `PackageExceptionRenderer` is registered by the host in `withExceptions`; it leaves unrelated, marker-only and non-JSON handling to the host. Its JSON envelope is `{message:string, code:string, context:object}`. Request locale is host-owned; diagnostics/previous exceptions are not public copy. Event schemas and source connections are documented in [events](docs/events.md).

The table lists enum discriminators, including any successful codes retained for compatibility. A code is not itself an HTTP status; the throwing exception's `suggestedStatus()` is authoritative, especially legacy/custom constructors. Empty context renders as `{}`; only documented JSON-safe context is presented.

| Code | Suggested status | Public context | Translation key |
| --- | --- | --- | --- |
| `operation_failed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.operation_failed` |
| `invalid_configuration` | 500 | {} | `nvl-auth::responsecode.invalid_configuration` |
| `feature_unavailable` | Exception-defined; see `suggestedStatus()` | {feature, operation, dependencies} | `nvl-auth::responsecode.feature_unavailable` |
| `invitation_invalid` | 410 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_invalid` |
| `invitation_principal_conflict` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_principal_conflict` |
| `invitation_identity_proof_required` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_identity_proof_required` |
| `invitation_unavailable` | 404/410 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_unavailable` |
| `invitation_resend_limited` | 429 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_resend_limited` |
| `invitation_assignment_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_assignment_invalid` |
| `invitation_exists` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_exists` |
| `invitation_registration_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_registration_invalid` |
| `invitation_delivery_metadata_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_delivery_metadata_invalid` |
| `unauthenticated` | 401 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.unauthenticated` |
| `authentication_required` | 401 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.authentication_required` |
| `forbidden` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.forbidden` |
| `api_token_ability_forbidden` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.api_token_ability_forbidden` |
| `tenant_context_required` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_context_required` |
| `system_mutation_forbidden` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.system_mutation_forbidden` |
| `tenant_membership_required` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_membership_required` |
| `verification_invalid` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.verification_invalid` |
| `recovery_code_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.recovery_code_invalid` |
| `tenant_authentication_intent_input_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_authentication_intent_input_invalid` |
| `tenant_authentication_intent_unavailable` | 410 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_authentication_intent_unavailable` |
| `tenant_authentication_intent_invalid` | 410 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_authentication_intent_invalid` |
| `invalid_audit_metadata` | 500 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_audit_metadata` |
| `tenant_audit_context_required` | 500 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_audit_context_required` |
| `credentials_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.credentials_invalid` |
| `membership_principal_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_principal_unavailable` |
| `membership_principal_ineligible` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_principal_ineligible` |
| `subject_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.subject_unavailable` |
| `subject_ineligible` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.subject_ineligible` |
| `membership_assignment_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_assignment_invalid` |
| `password_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.password_invalid` |
| `password_reset_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.password_reset_invalid` |
| `session_unavailable` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.session_unavailable` |
| `client_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_unavailable` |
| `client_redirect_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_redirect_invalid` |
| `client_origin_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_origin_invalid` |
| `client_session_input_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_session_input_invalid` |
| `client_session_ended` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_session_ended` |
| `client_session_conflict` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_session_conflict` |
| `client_session_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_session_unavailable` |
| `client_session_reason_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_session_reason_invalid` |
| `passkey_ceremony_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_ceremony_invalid` |
| `passkey_limit_reached` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_limit_reached` |
| `passkey_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_invalid` |
| `passkey_exists` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_exists` |
| `passkey_provider_unavailable` | 502 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_provider_unavailable` |
| `passkey_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_unavailable` |
| `passkey_input_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_input_invalid` |
| `passkey_counter_regression` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_counter_regression` |
| `passkey_backup_state_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_backup_state_invalid` |
| `passkey_user_verification_required` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_user_verification_required` |
| `social_provider_unavailable` | 404/502 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_provider_unavailable` |
| `social_identity_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_identity_unavailable` |
| `social_identity_conflict` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_identity_conflict` |
| `social_authorization_failed` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_authorization_failed` |
| `social_email_unverified` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_email_unverified` |
| `role_template_not_found` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_template_not_found` |
| `system_permission_immutable` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.system_permission_immutable` |
| `system_permission_delete_forbidden` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.system_permission_delete_forbidden` |
| `invalid_permission_catalog_query` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_permission_catalog_query` |
| `invalid_role_catalog_query` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_role_catalog_query` |
| `invalid_role_search` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_role_search` |
| `invalid_permission_search` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_permission_search` |
| `invalid_permission_group` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_permission_group` |
| `system_role_immutable` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.system_role_immutable` |
| `system_role_delete_forbidden` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.system_role_delete_forbidden` |
| `invalid_role_name` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_role_name` |
| `invalid_role_identifier` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_role_identifier` |
| `invalid_permission_identifier` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_permission_identifier` |
| `invalid_membership_filter` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_membership_filter` |
| `membership_revision_conflict` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_revision_conflict` |
| `membership_ownership_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_ownership_invalid` |
| `rbac_mixed_context_operation` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.rbac_mixed_context_operation` |
| `account_confirmation_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.account_confirmation_invalid` |
| `tenant_token_invalid` | 403 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_token_invalid` |
| `membership_last_owner` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_last_owner` |
| `membership_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_unavailable` |
| `principal_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.principal_unavailable` |
| `role_identifier_not_found` | 404/422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_identifier_not_found` |
| `permission_identifier_not_found` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.permission_identifier_not_found` |
| `ambiguous_role_identifier` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.ambiguous_role_identifier` |
| `ambiguous_permission_identifier` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.ambiguous_permission_identifier` |
| `duplicate_role_identifier` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.duplicate_role_identifier` |
| `duplicate_permission_identifier` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.duplicate_permission_identifier` |
| `too_many_role_identifiers` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.too_many_role_identifiers` |
| `too_many_permission_identifiers` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.too_many_permission_identifiers` |
| `invalid_role_parent` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_role_parent` |
| `role_hierarchy_cycle` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_hierarchy_cycle` |
| `totp_unavailable` | 404 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.totp_unavailable` |
| `totp_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.totp_invalid` |
| `self_delete_forbidden` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.self_delete_forbidden` |
| `invalid_bulk_selection` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_bulk_selection` |
| `self_bulk_operation_forbidden` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.self_bulk_operation_forbidden` |
| `self_disable_forbidden` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.self_disable_forbidden` |
| `invalid_user_filter` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_user_filter` |
| `invalid_user_search` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invalid_user_search` |
| `account_confirmation_required` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.account_confirmation_required` |
| `email_unavailable` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.email_unavailable` |
| `security_code_authentication_purpose_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.security_code_authentication_purpose_invalid` |
| `challenge_issue_conflict` | 409 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.challenge_issue_conflict` |
| `challenge_invalid` | 422 | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.challenge_invalid` |
| `logged_out` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.logged_out` |
| `password_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.password_updated` |
| `password_confirmed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.password_confirmed` |
| `email_verification_requested` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.email_verification_requested` |
| `roles_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.roles_listed` |
| `role_hierarchy_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_hierarchy_shown` |
| `role_templates_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_templates_listed` |
| `rbac_analytics_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.rbac_analytics_shown` |
| `role_created` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_created` |
| `role_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_shown` |
| `role_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_updated` |
| `role_cloned` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_cloned` |
| `role_template_applied` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_template_applied` |
| `role_deleted` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.role_deleted` |
| `passkey_registration_started` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_registration_started` |
| `passkey_registered` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_registered` |
| `passkey_revoked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_revoked` |
| `authenticated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.authenticated` |
| `invitations_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitations_listed` |
| `invitation_issued` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_issued` |
| `invitation_resent` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_resent` |
| `invitation_revoked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_revoked` |
| `rbac_synchronized` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.rbac_synchronized` |
| `permissions_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.permissions_listed` |
| `permission_created` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.permission_created` |
| `permission_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.permission_shown` |
| `permission_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.permission_updated` |
| `permission_deleted` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.permission_deleted` |
| `auth_audits_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.auth_audits_listed` |
| `auth_audit_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.auth_audit_shown` |
| `totp_enrollment_started` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.totp_enrollment_started` |
| `totp_enrolled` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.totp_enrolled` |
| `totp_verified` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.totp_verified` |
| `totp_revoked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.totp_revoked` |
| `passkey_authentication_started` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_authentication_started` |
| `passkey_authenticated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.passkey_authenticated` |
| `social_link_started` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_link_started` |
| `social_identity_linked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_identity_linked` |
| `social_identity_revoked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_identity_revoked` |
| `invitation_accepted` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.invitation_accepted` |
| `client_started` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_started` |
| `clients_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.clients_listed` |
| `client_created` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_created` |
| `client_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_shown` |
| `client_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_updated` |
| `client_deleted` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_deleted` |
| `client_activated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_activated` |
| `client_deactivated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.client_deactivated` |
| `social_authorization_started` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_authorization_started` |
| `social_authenticated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.social_authenticated` |
| `tenant_authentication_intent_completed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.tenant_authentication_intent_completed` |
| `memberships_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.memberships_listed` |
| `membership_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_shown` |
| `membership_enrolled` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_enrolled` |
| `membership_status_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_status_updated` |
| `membership_revoked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_revoked` |
| `membership_ownership_transferred` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.membership_ownership_transferred` |
| `users_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.users_listed` |
| `user_suggestions_listed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_suggestions_listed` |
| `user_created` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_created` |
| `user_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_shown` |
| `user_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_updated` |
| `user_enabled` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_enabled` |
| `user_disabled` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_disabled` |
| `user_deleted` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_deleted` |
| `user_restored` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_restored` |
| `users_bulk_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.users_bulk_updated` |
| `user_roles_synchronized` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_roles_synchronized` |
| `user_permissions_synchronized` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.user_permissions_synchronized` |
| `recovery_codes_regenerated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.recovery_codes_regenerated` |
| `recovery_code_consumed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.recovery_code_consumed` |
| `recovery_codes_revoked` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.recovery_codes_revoked` |
| `profile_shown` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.profile_shown` |
| `profile_updated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.profile_updated` |
| `account_deleted` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.account_deleted` |
| `magic_link_requested` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.magic_link_requested` |
| `magic_link_consumed` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.magic_link_consumed` |
| `security_code_requested` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.security_code_requested` |
| `security_code_verified` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.security_code_verified` |
| `security_code_authentication_requested` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.security_code_authentication_requested` |
| `security_code_authenticated` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.security_code_authenticated` |
| `email_verified` | Exception-defined; see `suggestedStatus()` | Declared safe scalar/array map; otherwise `{}` | `nvl-auth::responsecode.email_verified` |


## License

NVL Auth is released under the MIT License. See [LICENSE](LICENSE).
