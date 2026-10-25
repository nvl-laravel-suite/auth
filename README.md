# NVL Auth Light

Auth provides native Laravel service families for authentication, accounts, invitations, challenges, membership and security adapters. Required runtime dependencies are PHP 8.4, Laravel 13, Carbon and NVL Core. Package family metadata remains ^6.0 during the coordinated Light transition; the coordinated major release is separate.

Inject services from `Nvl\Auth\Services`. Inputs are explicit principals, native models, enums, scalar values and validated arrays. Reads return Eloquent models, collections, paginators or shaped arrays. Secret-bearing results retain redacted value objects. There are no operation Actions, execute interfaces, passive package DTOs or package-owned HTTP routes.

```php
$principal = $authentication->login(
    ['identifier' => $email, 'password' => $password],
    ['ipAddress' => $trustedIp, 'userAgent' => $userAgent],
    $guard,
    $session,
);
```

The consumer selects and supplies the StatefulGuard and Session. `verifyCredentials()` verifies credentials only. Complete login also enforces eligibility and challenge policy, runs the configured pipeline, records metadata and audit, rotates the supplied session and publishes committed facts. The consumer owns Request extraction, CSRF, throttles, redirects, cookies, headers and response presentation. Executable examples live in the package test consumer fixtures.

Management requires an explicit actor and an AuthManagementAccess decision; system mutations require an explicit SystemMutationContext and configured SystemMutationAccess. Defaults deny. Ambient Request/Auth state is never management authority or audit metadata. Configure the principal model, attribute mapper and narrow identity adapters for host principals. The base User has no Sanctum or Permission traits; opt into those traits on a consumer subclass when selecting those adapters.

Optional adapters retain Sanctum, Spatie Permission, Socialite, Google2FA and WebAuthn's audited engines. Install only selected engines and enable their feature flags. Bind SocialiteIdentityProvider with an explicitly constructed SDK driver and its provider name; the consumer owns Request/session acquisition and the SDK validates OAuth state. Never fabricate a verified external identity from untrusted callback fields. Passkey and second-factor verification retain challenge binding, expiry, replay and attempt/counter checks.

Native Ownership is optional. Declare and adopt the native owner graph before scoped traffic; use canonical owners and explicit membership/system authority. Owner selection proofs bind owner, purpose, browser session, subject when applicable and provider. Successful global authentication does not itself authorize owner entry or create membership. Old NVL Tenancy branches and automatic legacy-schema conversion are retired; retain old data and migration history and perform reviewed native adoption separately.

Auth sends no mail. Subscribe to `AuthDeliveryRequested` after source commit and transport its explicit immutable payload. Native ownership envelopes capture source facts for queued delivery; worker entry still revalidates owner/actor availability. Secret material stays out of logs and audit metadata. Audit and delivery remain tied to the outer source transaction; committed audit delivery preserves the existing durable retry protocol. A delivery outcome references the original invitation/message pair.

Configure `nvl-auth` deliberately. Host guards and password brokers remain host-owned. Optional Spatie storage adoption is explicit; schema readiness fails closed. Use `nvl:auth:features`, `nvl:auth:configuration`, `nvl:auth:schema` and `nvl:auth:doctor` to inspect the selected native graph. Choose one migration owner and review existing storage before applying schema changes.

See [native PHP API](docs/php-api.md), [upgrade notes](UPGRADING.md), [security](SECURITY.md), and the event definitions in `src/Events`. Tests cover direct native calls plus consumer HTTP, optional engines, native ownership and committed delivery.
