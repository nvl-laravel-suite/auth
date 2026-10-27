# NVL Auth Light

Auth provides native Laravel service families for authentication, accounts, invitations, challenges, membership and security adapters. Required runtime dependencies are PHP 8.4, Laravel 13, Carbon and NVL Core. NVL Light uses the coordinated 7.x package line.

Inject services from `Nvl\Auth\Services`. Inputs are explicit principals, native models, enums, scalar values and validated arrays. Reads return Eloquent models, collections, paginators or shaped arrays. Secret-bearing results retain redacted value objects. There are no operation Actions, execute interfaces, passive package DTOs or package-owned HTTP routes.

```php
$principal = $authentication->login(
    ['identifier' => $email, 'password' => $password],
    ['ipAddress' => $trustedIp, 'userAgent' => $userAgent],
    $guard,
    $session,
);
```

For stateless password authentication, use `Authentication::loginWithToken()`: it owns credential and enrolled factor proof, eligibility, the login pipeline, canonical rechecks, token issuance, metadata and committed audit/events. It never touches a web guard or session. `verifyCredentials()` proves credentials only. Browser consumers select and supply the StatefulGuard and Session. Native `login()` owns password and enrolled TOTP/recovery proof, canonical eligibility/password rechecks and session success. Missing enrolled proof throws `second_factor_required` and retains an opaque continuation only in that server session, backed by a locked existing Challenge row with five-minute expiry, five shared proof attempts and password binding; `hasPendingSecondFactor()` and `completeSecondFactor()` support the separate factor request without retaining the password. Raw token issuance also rechecks the persisted principal and its configured eligibility before issuing, including custom provider adapters. Consumers own Request extraction, CSRF, throttles, redirects, cookies, headers and response presentation. Executable examples live in the package test consumer fixtures.

Management requires an explicit actor and an AuthManagementAccess decision; system mutations require an explicit SystemMutationContext and configured SystemMutationAccess. Defaults deny. Ambient Request/Auth state is never management authority or audit metadata. Configure the principal model, attribute mapper and narrow identity adapters for host principals. The base User has no Sanctum or Permission traits; opt into those traits on a consumer subclass when selecting those adapters.

Optional adapters retain Sanctum, Spatie Permission, Socialite, Google2FA and WebAuthn's audited engines. Install only selected engines and enable their feature flags. Bind SocialiteIdentityProvider with an explicitly constructed SDK driver and its provider name; the consumer owns Request/session acquisition and the SDK validates OAuth state. Never fabricate a verified external identity from untrusted callback fields. Passkey and second-factor verification retain challenge binding, expiry, replay and attempt/counter checks.

Native Ownership is optional. Declare and adopt the native owner graph before scoped traffic; use canonical owners and explicit membership/system authority. Owner selection proofs bind owner, purpose, browser session, subject when applicable and provider. Successful global authentication does not itself authorize owner entry or create membership. Old NVL Tenancy branches and automatic legacy-schema conversion are retired; retain old data and migration history and perform reviewed native adoption separately.

Auth sends no mail. Subscribe to `AuthDeliveryRequested` after source commit and transport its explicit immutable payload. Native ownership envelopes capture source facts for queued delivery; worker entry still revalidates owner/actor availability. Secret material stays out of logs and audit metadata. Audit and delivery remain tied to the outer source transaction; committed audit delivery preserves the existing durable retry protocol. A delivery outcome references the original invitation/message pair.

Configure `nvl-auth` deliberately. Host guards and password brokers remain host-owned. Optional Spatie storage adoption is explicit; schema readiness fails closed. Use `nvl:auth:features`, `nvl:auth:configuration`, `nvl:auth:schema` and `nvl:auth:doctor` to inspect the selected native graph. Choose one migration owner and review existing storage before applying schema changes.

See [native PHP API](docs/php-api.md), [upgrade notes](UPGRADING.md), [security](SECURITY.md), and the event definitions in `src/Events`. Tests cover direct native calls plus consumer HTTP, optional engines, native ownership and committed delivery.

Stateful TOTP continuation requires the existing Auth challenges store even when magic links and security codes are disabled. The schema plan/doctor includes that dependency. Existing partial installations use the normal reviewed `nvl:auth:schema --apply` workflow, or update their published host migration; no new table shape or migration file is introduced.
