# NVL Auth

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
php artisan vendor:publish --tag=auth-migrations
php artisan vendor:publish --tag=auth-skills
php artisan migrate
php artisan nvl:auth:doctor
```

Package discovery registers `AuthServiceProvider`. With the default
configuration NVL Auth supplies the application's authentication User model,
password-reset repository, Spatie Role and Permission models, and Sanctum
PersonalAccessToken model. Routes remain off until explicitly enabled.

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
to operate on the configured class.

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
    public function orders(): HasMany
    {
        return $this->hasMany(Order::class);
    }
}
```

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
        // Map $event->request into nvl/mail-notifications or another transport.
    }
}
```

Auth owns the message intent and secure payload. The consumer owns channel,
template, provider, delivery retry, and provider callback concerns.

## Storage

The complete schema is always installed, independently of feature and route
flags. It contains 17 UUID-first, `nvl_auth_`-prefixed tables: User, RBAC and
pivots, Sanctum tokens, password resets, clients/session correlations,
invitations, challenges, TOTP, passkeys, recovery codes, social identities, and
audits. It intentionally contains no mail delivery, notification, queue,
outbox, workflow, or maintenance-checkpoint tables.

See [schema](docs/schema.md) for the exact inventory.

## Operations

```bash
php artisan nvl:auth:features
php artisan nvl:auth:features --format=json
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
