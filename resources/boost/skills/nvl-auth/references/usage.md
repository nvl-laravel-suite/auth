# Native Auth consumer guide

Use [installation](installation.md) for exact providers/publication/schema/adapter choices and [API](api.md) for every public declaration and input/result shape. Services live in `Nvl\Auth\Services`. Consumers own HTTP, request extraction, CSRF/throttles, redirects, cookies, mail delivery UI, DTOs and resource projection.

## Capability selection

| Consumer requirement | Native family and operations |
| --- | --- |
| Password authentication | `Authentication::login`, `loginWithToken`; optional `proveCredentials` / `proveCredentialsForToken`; `verifyCredentials` is credential proof only |
| Browser finalization/logout/MFA | `AuthenticationSessions::establishFromProof`, `logout`; `Authentication::hasPendingSecondFactor` / `completeSecondFactor` |
| Password registration | `AuthRegistration::register`; social registration/verified mailbox continuation methods |
| Principal administration/self profile | `AuthUsers::create`, `update`, `setActive`, `delete`, `restore`, bounded `bulkUpdate`, `updateProfile`, `deleteOwnAccount` |
| Principal reads | `AuthUserReader::profile`, `find`, `paginate`, `suggest` |
| Password/reset/email methods | `AuthPasswords::requestReset`, `reset`, `update`, `setInitial`, `remove`; `AuthEmailVerification::request` / `verify`; `AuthEmailChanges::request` / `complete` / `cancel` |
| Email magic links/codes | `AuthChallenges` generic issue/consume, and separate authentication-specific request/proof/finalization methods |
| Invitations | `AuthInvitations::create`, `findActive`, `paginate`, `preview`, `register`, `registerSocial`, `accept`, `resend`, `revoke`, `recordDeliveryOutcome` |
| Native recent confirmation | `AuthReauthentication::confirm` with one primary proof and optional enrolled factor |
| TOTP/recovery | `AuthSecondFactor::startEnrollment`, `confirmEnrollment`, `verify`, `revoke`, `state`, recovery generation/consumption/revocation |
| WebAuthn | `AuthPasskeys` registration/authentication/reauthentication begin/finish and revoke |
| OAuth login/linking | `AuthSocialAuthentication` begin/complete login or reauthentication; `AuthSocialLinks` begin/complete link/reconnect and unlink |
| API tokens | `AuthTokens::create`, `all`, `rotate`, `update`, `revoke`, `revokeAll`, `authenticateFromProof`; complete credential auth uses `loginWithToken` |
| Browser grant management | `AuthBrowserSessions::paginate`, `admit`, `revoke`, `revokeOthers`, `revokeAll`; `AuthRememberCredentials::resume` rotates device proof |
| Client handoff/session observations | `AuthClients::create`, `update`, `delete`, `setActive`, `find`, `paginate`, `start`, `recordSession`, `touchSession`, `endSession` |
| Owner membership | `AuthMemberships::provision`, `enroll`, `own`, `find`, `paginate`, `setStatus`, `transfer`, `revoke`; native revision checks |
| RBAC writes | `AuthRoles` CRUD, duplicate, permission assignment/template application/sync and principal role sync; `AuthPermissions` CRUD, catalog/combined sync, bootstrap and principal permission sync |
| RBAC reads | `AuthRbacReader` role/permission catalogs, options/suggestions, hierarchy, templates, exact identifier resolution, analytics and name availability |
| Account method inventory/recovery | `AuthAccountSecurity::state`; separately authorized `AuthAccountRecovery::recover` with complete session/token containment |
| Impersonation | `AuthImpersonation::start`, `admit`, `stop`, `revoke`; `Adapters\Laravel\LaravelImpersonation` owns temporary guard/session transitions |
| Audit/retention/adoption | `AuthAuditReader::find` / `paginate`; `AuthMaintenance::prune` / `adoptPrincipals`; feature/schema/doctor commands and `PrincipalEmailIdentityAdoption` |
| Narrow integrations | `FeatureGate`, `SocialProviderRegistry`, `OwnerAuthenticationIntents`, `AuthOwnerAdmission`, `AuthExecutionContext` and proof/assurance contracts: use their API-defined capability, not a raw-principal login shortcut |

## Host authority, identity and extension choices

Bind `AuthManagementAccess` to actual host permissions. The default Laravel Gate adapter needs deliberate ability grants; the configured-policy alternative delegates only configured aliases/policy models. Explicit system mutations use `Nvl\Auth\ValueObjects\SystemMutationContext(reason, correlationId, actor:null, metadata:[])` and a separately bound `SystemMutationAccess`; context construction alone grants nothing. Impersonation additionally requires `ImpersonationAccess`.

Configure the host principal provider, `PrincipalAttributeMapper`, narrow `AuthSubjectResolver` / `AuthIdentifierResolver` where needed, `AuthenticationEligibility` and method policies. Native services canonicalize/recheck principals at security boundaries; never pass caller-modified user attributes as policy evidence. Non-Eloquent providers retain their external freshness contract. `PrincipalExtensionMapper` is the explicit seam for application fields; default extension handling rejects unsupported data.

Feature model selections are `features.principal_management.models.user`, `features.rbac.models.role`, `.permission`, `.principal`, `features.api_tokens.models.personal_access_token`, `features.memberships.models.membership`, all below `nvl-auth`. Configure before boot; preserve supported native keys, casts, storage, query/persistence hooks and ownership. RBAC principal is an Eloquent Authenticatable with required Permission methods; the base User has no engine traits. The host decides whether to use the package user as Laravel auth model. Model replacement does not migrate populated principal or permission storage.

Install/enable only selected adapters: Sanctum for its token manager, Spatie Permission for RBAC, Socialite for OAuth, Google2FA for TOTP, WebAuthn for passkeys. Disabled paths boot with those engines absent and reject explicitly unavailable operations. Feature names include `registration`, `authentication`, `principal_management`, `memberships`, `password`, `email_verification`, `magic_links`, `security_codes`, `invitations`, `totp`, `passkeys`, `recovery_codes`, `social_identities`, `clients`, `impersonation`, `managed_sessions`, `sessions`, `api_tokens`, `rbac`, `audit`. Enabling a feature does not grant permission or erase existing enrolled factors when later disabled.

## Closed native array contracts

Use the full API reference for required/nullable types and defaults; these field names prevent transport aliases and protected fields from reaching services:

| Operation input | Accepted fields / semantics |
| --- | --- |
| Password credentials | Exactly `identifier`, `password`; bounded nonempty strings |
| Browser login context | Trusted `AuthenticationRequestContext` facts plus optional exact boolean `remember`; login supplies guard/session bindings itself |
| Stateless login context | Only nullable `ipAddress`, `userAgent`, `requestId` |
| Factor proof | `code` or `recoveryCode`, never both |
| Token create/update/rotate | `name`, nonempty distinct list `abilities`, optional `expiresAt` (`CarbonImmutable|null`); omission means null expiry, not a patch-preserved expiry |
| Password registration | `name`, `email`, `password`, `passwordConfirmation`, optional `locale`, `timezone`, `extensions` |
| Social registration | `name`, optional `locale`, `timezone`, `extensions`; verified email/provider identity come from native continuation |
| Admin principal create | `name`, `email`, explicit `password` string or null; optional `active`, `locale`, `timezone`, `profile`, `preferences`, `roles`, `permissions`, `emailVerified`, `extensions` |
| Admin principal update | `name`, `email`, `password`, `locale`, `timezone`, `profile`, `preferences`, `emailVerified`, `extensions`; status changes use `setActive(['active'=>bool])` |
| Self profile | `name`, `locale`, `timezone`, `profile`, `preferences`, `extensions`; use staged `AuthEmailChanges` for mailbox replacement |
| Password reset | `identifier`, `token`, `password`, `passwordConfirmation`; reset request takes `identifier`; update/setInitial takes password pair |
| Recent confirmation | Exactly one `password`, `passkeyProof` or `socialProof`; optional one `code` / `recoveryCode` |
| Magic-link request / consume | Request `recipient`, `purpose`; consume `recipient`, `token`, optional `challengeId` as declared |
| Security-code request / verify | Request `recipient`, `purpose`; verify adds `code` |
| Invitation creation | `recipient`, `type`, `purpose`, `roles`, `permissions`, `metadata`, `locale`, `context`; private issuance context is a separate value |
| Invited registration | `token`, `name`, `registrationMethod`, `password`, `passwordConfirmation`, `locale`, `timezone`, `extensions`, according to selected method |
| TOTP enrollment/proof | Enrollment `accountName`, `name`; verification/recovery consumption uses `code` |
| Passkey completion | `ceremonyId`, `response`; registration additionally permits `name` |
| Role create/update | `name`, `displayName`, `description`, `parentId`, `priority`, `system`, `permissions`, `metadata`; apply-template uses `template`, `roleName` |
| Permission create/update | `name`, `displayName`, `description`, `group`, `system`, `metadata` |
| Principal RBAC assignment | Exactly `roles` or `permissions` according to the operation |
| Client create/update | `name`, `surface`, `baseUrl`, `returnPaths`, `allowedOrigins`, `allowedFlows`, `metadata`, `active`; start uses `clientId`, `flow`, `returnPath`, `origin` |
| Impersonation start | Required bounded `reason`, optional integer `durationSeconds` (60–1800) |
| Support recovery | Required `reason`; optional `correlationId`, `revokeSessions`, `revokeTokens`, `passkeyIds`, `socialIdentityIds`, `totpIds`, `revokeRecoveryCodes`; session/token containment must remain true |

Patch operations preserve omitted supported fields. Do not generically remove nulls: nullable password removal/expiry/role fields and explicit empty arrays have operation-specific meaning. A self-service mailbox change is staged/proven through `AuthEmailChanges`, not a generic profile email replacement. The host chooses locale/timezone for provisioning and explicit delivery locale; never borrow ambient job Request/Auth authority. Protected IDs, owners, security revisions and proof attributes are never mass assignable through these arrays.

## Verified browser password login and factor continuation

Preconditions: native schema installed, configured `web` guard/provider, sessions/authentication enabled and a persisted eligible principal. The host controller extracts credentials and trusted request metadata:

```php
use Illuminate\Support\Facades\Auth;
use Nvl\Auth\Services\Authentication;

$authentication = app(Authentication::class);
$guard = Auth::guard('web');
$session = $request->session();
$subject = $authentication->login(
    ['identifier' => $email, 'password' => $password],
    ['ipAddress' => $request->ip(), 'userAgent' => $request->userAgent()],
    $guard,
    $session,
);
```

The guard must be the configured `nvl-auth.authorization.guard`. Native login checks enrolled factors. If `AuthException::$errorCode === 'second_factor_required'`, render the host factor form while retaining the same server session. A later request calls:

```php
$subject = $authentication->completeSecondFactor(
    ['code' => $submittedTotp],
    $guard,
    $request->session(),
);
```

`hasPendingSecondFactor($session)` indicates the pending flow. No password is retained. Final continuation/proof expiry is 300 seconds with five shared failed attempts and one-use consumption; stale snapshots, changed password/security revision, unavailable factors or disabled principals reject. Recovery is a factor after primary proof, never a primary login method. `AuthenticationAssurancePolicy` may strengthen native assurance and cannot bypass enrollment.

## Stateless factor continuation across requests

Use `loginWithToken(..., factorProof: [...])` when password and factor arrive together. For a separate token-client factor request, own the continuation in the host; `completeSecondFactor` is the browser/session operation and cannot finish this flow.

`proveCredentialsForToken` returns `IssuedAuthenticationProof`, with only explicit `reveal()` access to its bearer. It has no `pending`, `expiresAt`, subject or token result fields. Attempt the native token finalizer to detect required MFA: `second_factor_required` means assurance rejected before consuming that proof. Credential verification alone does not indicate whether MFA remains necessary.

With native proof schema, API tokens, enrolled factor adapters and a transactional token manager configured, initiate outside a host transaction. The token abilities below are host-approved, not copied from an arbitrary client request:

```php
use Illuminate\Support\Facades\Crypt;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

$context = new AuthenticationRequestContext(
    tokenNamespace: 'mobile',
    flowNonce: bin2hex(random_bytes(32)),
);
$token = ['name' => 'Mobile', 'abilities' => ['profile:read']];
$issued = app(Authentication::class)->proveCredentialsForToken(
    ['identifier' => $email, 'password' => $password],
    $context,
);
$sealedContinuation = null;
try {
    $result = app(AuthTokens::class)->authenticateFromProof($issued->reveal(), $token, $context);
} catch (AuthException $exception) {
    if ($exception->errorCode !== 'second_factor_required') {
        throw $exception;
    }
    $sealedContinuation = Crypt::encryptString(json_encode([
        'proof' => $issued->reveal(),
        'context' => $context->facts(),
        'token' => $token,
    ], JSON_THROW_ON_ERROR));
}
```

If finalization succeeded, deliver its token result and create no pending flow. Otherwise keep `$sealedContinuation` in private server-side storage, addressed by a host-defined opaque handle bound to the initiating client. The handle/storage mechanism is consumer-owned, not a native Auth result. Keep its lifetime within the original proof's 300-second deadline from issuance; retries must not reset it. Retain no password or submitted factor. Store the revealed string deliberately rather than serializing `IssuedAuthenticationProof`, whose JSON/PHP serialization throws. Retain `context->facts()` explicitly: generic context JSON is redacted and cannot reconstruct the token binding. Keep the original namespace, nonce, any other captured context facts and approved token request unchanged across requests.

For the subsequent factor request, load the private encrypted record only after the host validates its flow handle/client binding. The following assumes `$sealedContinuation` came from that host storage, never a client-supplied context array:

```php
use Illuminate\Support\Facades\Crypt;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Services\AuthenticationProofs;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

$pending = json_decode(Crypt::decryptString($sealedContinuation), true, 512, JSON_THROW_ON_ERROR);
$context = AuthenticationRequestContext::fromFacts($pending['context']);
$completed = app(AuthenticationProofs::class)->completeFactor(
    $pending['proof'],
    AuthenticationDestination::ApiToken,
    $context,
    ['code' => $submittedTotp],
);
$result = app(AuthTokens::class)->authenticateFromProof(
    $completed->reveal(),
    $pending['token'],
    $context,
);
$subject = $result['subject'];
$issuedToken = $result['token'];
$plainTextToken = $issuedToken->plainTextToken;
$tokenMetadata = $issuedToken->token;
```

Use exactly one `['code' => $submittedTotp]` or `['recoveryCode' => $submittedRecoveryCode]`. `completeFactor` records native factor verification on the same capability, returns another `IssuedAuthenticationProof` wrapping the same bearer, and does not extend expiry, consume final authentication or issue a token. Follow it with `authenticateFromProof`; do not call `consume` separately first. The finalizer rechecks assurance/canonical state, consumes once, runs login/token pipelines and returns exactly `array{subject: Authenticatable, token: IssuedApiToken}`. Token metadata contains `id`, `name`, `abilities`, `lastUsedAt`, `expiresAt`, `createdAt`; the one-time bearer is the separate `plainTextToken` property. Clear host pending storage after success and project the intended token response without logging secrets. If the host supports token expiry, restore `expiresAt` as `CarbonImmutable|null`, not a decoded JSON string; this example omits it.

Failure handling preserves the native order:

- A `totp_invalid` or `recovery_code_invalid` failure spends a stored factor attempt. Preserve the same encrypted continuation and original deadline only while `AuthenticationProofs::available($pending['proof'])` remains true; the shared failed-attempt budget is five. Availability is a non-consuming validity check, not MFA detection, destination/context verification or authentication authority.
- Expiry, exhausted attempts, changed password/security revision, unavailable principal or wrong original context fail closed. Clear unusable pending storage and require a new primary flow; never manufacture verified factor flags or change destination/nonce to rescue a proof.
- Successful factor verification spends the TOTP timestep/recovery code before finalization. Outside an enclosing source transaction, a later login/token-pipeline failure leaves the final proof consumed, even when token writes roll back. Do not rerun factor completion or present a spent bearer as retryable. An explicit same-source outer rollback has its separately documented native transactional behavior; this cross-request recipe uses no outer transaction. Do not retain bearer proofs, factor values or issued token plaintext in logs/error bodies.

## Proof composition and recent authentication

Prefer complete operations. For a browser-specific email/passkey/social workflow, use native verified proof initiation and `AuthenticationSessions::establishFromProof` with its original trusted context. Session proofs bind guard/session; token proofs bind `tokenNamespace` and a random `flowNonce` of at least 32 characters. Destinations are not interchangeable. Never replace finalization with `guard->login($rawPrincipal)`.

`AuthChallenges` generic delivery challenges do not authenticate. Use its authentication-specific methods with unchanged context. Passkey finish returns subject, proof and native requestContext; finalize using that returned context. Verified UV passkeys may satisfy native MFA; other primary methods retain enrollment enforcement.

Recent confirmation example for an authenticated resettable principal, outside its source transaction:

```php
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

$context = new AuthenticationRequestContext(
    guardName: 'web',
    sessionBinding: $request->session()->getId(),
);
$grant = app(AuthReauthentication::class)->confirm(
    $subject,
    ['password' => $currentPassword, 'code' => $submittedTotp],
    RecentAuthenticationPurpose::PasswordChange,
    $context,
);
app(AuthPasswords::class)->update(
    $subject,
    ['password' => $newPassword, 'passwordConfirmation' => $newPassword],
    $grant->reveal(),
    $context,
);
```

If the principal has no required factor, omit `code`. With managed sessions enabled supply the native admitted browser context as well, rather than inventing binding values. Recent grants bind canonical subject, security revision, purpose and trusted browser context for 300 seconds. Self password/email/deletion, factor enrollment/removal, recovery regeneration and social link/unlink/reconnect consume the matching grant inside their mutation transaction. A security revision change requires a fresh confirmation for the next mutation. Ordinary `auth.password_confirmed_at` is presentation only.

## OAuth, passkeys, tokens and browser containment

Bind `SocialIdentityProviderFactory` as a scoped host service before Auth registers. `make(provider)` must construct a fresh `SocialiteIdentityProvider` and SDK driver from the current Request/session for every operation; do not return Socialite manager's cached driver. Preserve SDK OAuth state verification. `beginLogin` returns URL/redacted intent; retain intent and original context privately in the initiating browser, then `completeLogin`. Only exact active immutable links authenticate; email matching cannot attach an account. `registration_required` yields a short-lived redacted continuation for `AuthRegistration`, never raw callback identity claims. Provider-specific support for reauthentication is explicit.

Link/reconnect initiations consume purpose-specific recent grants before redirect; their completions use verified SDK claims. Unlink cannot remove the final usable primary method. Passkey ceremonies require configured relying party/origins, session-bound challenge, original native completion data and SDK verification. Consumer hooks cannot rewrite canonical principal identity or disable mandatory checks.

`Authentication::loginWithToken(credentials, token, context:[], factorProof:[])` is complete stateless password authentication. It returns `subject` and `IssuedApiToken`. Its manager implements `TransactionalApiTokenManager`; principal, native audit and token writes share one source. It never uses a web session. Raw `AuthTokens::create` is token management and still rechecks eligibility; it is not credential login. Authentication/recent proof values use explicit `reveal()` accessors. `IssuedApiToken` exposes `token` metadata and one-time `plainTextToken`; project the intended response explicitly and never log or generically serialize the secret-bearing result.

Managed sessions use `AuthBrowserSessions` authoritative grants and optional native Laravel admission/guard adapters; enrollment belongs to successful native authentication. `AuthRememberCredentials::resume` rotates selector/secret into primary proof and retains MFA/browser admission. Impersonation requires `ImpersonationAccess`, reason, recent purpose grant and short expiry. `LaravelImpersonation` handles guard/session rotation/restoration. `AuthExecutionContext::facts` is bounded audit attribution and never portable queue execution authority. Support recovery requires separate recovery permission and complete managed session/token containment.

## Owner membership, RBAC and bounded reads

`nvl-auth.ownership.scoped=true` requires native Ownership resource registration, reviewed principal/membership adoption and live admission. Complete `OwnerReference`/subject references and owner-intent nonce/purpose/session/provider bindings are trusted native values, not request tenant IDs. `OwnerAuthenticationIntents` issue/consume an exact one-use owner selection intent; selection admission does not enter a privileged execution scope. Membership provision/enroll/status/transfer/revoke retain expected revisions, owner constraints and principal eligibility.

RBAC catalogs/templates use `PermissionCatalogProvider`, `RoleTemplateProvider`, native registries and `RbacPrincipalAccess`. Choose principal/role/permission models before boot. Catalog sync transacts on configured Permission storage. Template application/sync, combined sync and bootstrap require Role and Permission on the same actual connection and reject splits before writing; success audit follows that source's outer commit. Role hierarchy/cycles, protected system fields and super-admin assignment remain native policy. Do not reproduce native pivot writes or cache invalidation in controllers.

Use `AuthUserReader`, `AuthRbacReader`, `AuthInvitations::paginate`, `AuthMemberships::paginate`, `AuthClients::paginate`, `AuthAuditReader::paginate` and `AuthBrowserSessions::paginate` for authorized bounded reads. Per-page/option/identifier lists have configured caps; user bulk mutations accept at most 100 UUIDs and cannot target the executing actor. Filter arrays/sorts and safe outputs are enumerated in the API. Native models remain useful for trusted composition, but raw queries do not replace management admission or secret-aware projections.

## Source transactions, delivery and operations

Browser transitions call `assertCanTransition` before proof/SDK/session effects; login, finalization, factor completion, logout and self-delete enforce it. They reject an active actual principal/proof/audit source transaction with `stateful_transaction_unsupported` (409). Commit registration before login, and do not wrap self-delete-with-logout in a host domain transaction. Browser failure cleanup invalidates partial session/CSRF state; framework/external effects cannot be un-fired by SQL rollback.

Ordinary native domain/proof writes may join their actual source transaction. Audit/external delivery events follow source outer commit and disappear on rollback. Native recent confirmation commits its factor proof before the guarded mutation; mutation rollback restores the consumed grant/mutation, while the earlier factor remains spent. Stateless native transactional token rollback restores participating proof/token/fact state. Never replace native source checks with consumer transaction wrappers.

Auth emits typed delivery requests; host listeners/adapters deliver password reset, email verification, magic link/code and invitation copy. Preserve locale, expiry, one-use tokens and native delivery context. Neutral request responses must not reveal whether an identifier exists. Hook stages receive bounded operation facts, not credentials, factor codes, bearer proofs or password fingerprints.

Commands include `nvl:auth:features`, `nvl:auth:configuration`, `nvl:auth:configure`, `nvl:auth:schema`, `nvl:auth:doctor`, `nvl:auth:prune --dry-run`, `nvl:auth:adopt-principals`, `nvl:auth:adopt-email-identities`; installation/API give exact flags and one migration-owner choice. Schema includes mandatory proof/security-state storage even with optional methods disabled. Canonical email identity uses UTF-8 lowercase/trim without provider-specific rewriting. Adoption plans report missing/colliding keys; apply requires explicit system authority and drained legacy writers, with host DDL remaining host-owned.

`AuthException` exposes `errorCode`, `status`, bounded `context`; host controllers map these deliberately. Invalid shapes may throw `InvalidArgumentException` or `ValidationException`; management failures deny. Native secret results remain redacted and some forbid JSON/PHP serialization. Do not turn diagnostics, secret request values or provider callback payloads into public error bodies.
