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

Optional adapters retain Sanctum, Spatie Permission, Socialite, Google2FA and WebAuthn's audited engines. Install only selected engines and enable their feature flags. Bind SocialIdentityProviderFactory as a scoped host service before the Auth provider registers. Its make method must construct a fresh SocialiteIdentityProvider and SDK driver for every operation, obtaining the current Request and session at that time; the SDK validates OAuth state. Do not return cached Socialite manager drivers. Never fabricate a verified external identity from untrusted callback fields. For example, a GitHub-only host factory can construct a driver directly instead of using Socialite's cached manager:

```php
use Laravel\Socialite\Two\GithubProvider;
use Nvl\Auth\Adapters\Socialite\SocialiteIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;

final class GithubIdentityProviderFactory implements SocialIdentityProviderFactory
{
    public function make(string $provider): SocialIdentityProvider
    {
        if ($provider !== 'github') {
            throw new InvalidArgumentException('Unsupported social provider.');
        }

        $config = config('services.github');
        $driver = new GithubProvider(request(), $config['client_id'], $config['client_secret'], $config['redirect']);

        return new SocialiteIdentityProvider($driver, $provider);
    }
}

$this->app->scopedIf(SocialIdentityProviderFactory::class, GithubIdentityProviderFactory::class);
```

Native principal management accepts an explicit `extensions` array for host fields. Configure `features.principal_management.services.extension_mapper` with a `PrincipalExtensionMapper`; its `validateAndMap(PrincipalMutation $mutation, array $extensions, ?User $principal = null): array` validates logical fields and returns physical columns. Use a subclass of `Nvl\Auth\Models\User` with those columns explicitly fillable. The mapper runs inside the native mutation transaction and must not persist, issue credentials, mutate ownership or perform external effects. A consumer Action can compose complete native operations for related records. The default rejects nonempty extensions; input and output are limited to 16 KiB of JSON at depth 16. Native fields, mapped aliases, identity hashes, ownership and security columns remain protected.

For example, a host model can declare `protected $fillable = ['job_title'];`. Its mapper validates `jobTitle` using `['sometimes', 'nullable', 'string', 'max:100']` and returns `array_key_exists('jobTitle', $validated) ? ['job_title' => $validated['jobTitle']] : []`. Call `$users->updateProfile($principal, ['extensions' => ['jobTitle' => null]])` to clear it explicitly; omitting the field preserves its value. The executable `ExtensionPrincipal` and `TestPrincipalExtensionMapper` test fixtures show this complete mapping. Invitation extensions use the same bounded mapper and are no longer copied into canonical profile JSON by the default invitation mapper.

Passkey and second-factor verification retain challenge binding, expiry, replay and attempt/counter checks.

Native Ownership is optional. Declare and adopt the native owner graph before scoped traffic; use canonical owners and explicit membership/system authority. Owner selection proofs bind owner, purpose, browser session, subject when applicable and provider. Successful global authentication does not itself authorize owner entry or create membership. Old NVL Tenancy branches and automatic legacy-schema conversion are retired; retain old data and migration history and perform reviewed native adoption separately.

Auth sends no mail. Subscribe to `AuthDeliveryRequested` after source commit and transport its explicit immutable payload. Native ownership envelopes capture source facts for queued delivery; worker entry still revalidates owner/actor availability. Secret material stays out of logs and audit metadata. Audit and delivery remain tied to the outer source transaction; committed audit delivery preserves the existing durable retry protocol. A delivery outcome references the original invitation/message pair.

Configure `nvl-auth` deliberately. Host guards and password brokers remain host-owned. Optional Spatie storage adoption is explicit; schema readiness fails closed. Use `nvl:auth:features`, `nvl:auth:configuration`, `nvl:auth:schema` and `nvl:auth:doctor` to inspect the selected native graph. Choose one migration owner and review existing storage before applying schema changes.

See [native PHP API](docs/php-api.md), [upgrade notes](UPGRADING.md), [security](SECURITY.md), and the event definitions in `src/Events`. Tests cover direct native calls plus consumer HTTP, optional engines, native ownership and committed delivery.

Authentication requires native proof storage and consistent enrolled MFA across all login methods. Run the forward proof-storage migration and migrate bare-principal completion as described in [upgrade notes](UPGRADING.md).

Native recent authentication now authorizes sensitive self-service operations. Call `AuthReauthentication::confirm()` before starting a mutation transaction, then pass its opaque grant and the trusted `AuthenticationRequestContext` to the operation. Grants are subject/purpose/guard/session/revision-bound, expire at 300 seconds and are one-use; mutation rollback restores the grant but never the previously committed factor proof. Replace `currentPassword` mutation fields and raw `AccountConfirmation` implementations with the safe evidence/purpose policy contract. Laravel password-confirmed timestamps are presentation only. Passwordless UV passkeys are supported; linked-social reauthentication is explicitly unavailable until its receipt integration. Administrative/system authorization remains separate. See [the PHP API](docs/php-api.md#native-recent-authentication).

Browser transitions now reject an enclosing transaction on their participating native source connections with `stateful_transaction_unsupported` (409), before consuming proof or changing the guard/session. Commit registration/domain work first, then log in; self-deletion with logout must likewise start outside a host transaction. Standalone persisted proofs and stateless token operations remain transaction-aware. For a consumer composition that immediately establishes a session, call `AuthenticationSessions::assertCanTransition()` before invoking a primary verifier/SDK or pulling OAuth session state. Native finalizers also enforce the boundary. Immediate login failure clears partial browser state, invalidates the session and rotates CSRF; a failed session rotation cannot count as success. Laravel guard events can already have fired before later failure and cannot be retracted; native domain success follows its owning commit. Custom guards/session stores must honor their own logout/invalidation contracts.

Native email identities use a protected normalized SHA-256 key, reserved through soft deletion. Retained deployments must explicitly plan/apply email-key adoption and finalize schema before native email lookup; see [UPGRADING.md](UPGRADING.md). Initial email verification consumes the private token emitted by `AuthEmailVerification::request`, through `verify($subject, $token)`. Consumers own delivery, routes and responses.

Public password signup uses `AuthRegistration::register(['name' => $name, 'email' => $email, 'password' => $password, 'passwordConfirmation' => $confirmation, 'extensions' => $hostFields])`. Registration defaults disabled and `features.registration.settings.mode` defaults to `closed`; explicitly enable it and select `open` for public signup or `invitation_only` for new invited principals. Configure `features.registration.services.admission` with a `RegistrationAdmission` host policy; native mode checks remain mandatory. Its validated extensions are physical host fields after bounded mapping. The result is an active, unverified configured User subclass with no login, membership or RBAC grant. Selected native email verification emits delivery after the outer source commit, without sending mail.

Consumers own signup routes, validation/response mapping, rate limits and onboarding orchestration. Compose related native domain operations inside an application-owned transaction, commit, then authenticate in a separate browser operation. `registration_unavailable` is a stable conflict code; a consumer may present a neutral response as shown by the RegistrationController fixture. A post-commit listener failure does not undo the account: retrying signup can return the conflict. Native `PrincipalRegistered` is the registration fact; bridge Laravel Registered deliberately only if desired.

Existing authenticated-recipient invitation acceptance, revocation and cleanup retain their own proof rules when signup is closed. New invitation consumers must opt into registration and InvitationOnly/Open. A request `registrationMethod=social` is never verified authority and new social provisioning is currently unavailable pending the native verified social continuation workflow. Existing-subject SocialSubjectResolver adapters must not perform raw, quiet or ordinary creation; native Eloquent creation is rejected inside the resolver transaction.
