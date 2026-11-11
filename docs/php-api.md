# Native Auth service API

Inject the following families from `Nvl\Auth\Services`. Signatures below reflect source. Parameter array shapes and validation are documented with each implementation. There are no operation aliases.

## Authentication

```php
public function loginWithToken(#[SensitiveParameter] array $credentials, array $token, array $context = [], #[SensitiveParameter] array $factorProof = []): array;
public function login(#[SensitiveParameter] array $credentials, array $context, StatefulGuard $guard, Session $session, #[SensitiveParameter] array $factorProof = []): Authenticatable;
public function hasPendingSecondFactor(Session $session): bool;
public function completeSecondFactor(#[SensitiveParameter] array $factorProof, StatefulGuard $guard, Session $session): Authenticatable;
public function verifyCredentials(#[SensitiveParameter] array $credentials): Authenticatable;
public function proveCredentials(#[SensitiveParameter] array $credentials, AuthenticationRequestContext $context): IssuedAuthenticationProof;
public function proveCredentialsForToken(#[SensitiveParameter] array $credentials, AuthenticationRequestContext $context): IssuedAuthenticationProof;
```

`loginWithToken()` is the complete stateless password operation. Credentials contain
`identifier` and `password`; token input contains `name`, `abilities` and optional
`expiresAt` (`CarbonImmutable|null`). Context accepts `ipAddress`, `userAgent` and
`requestId`. Supply either `code` or `recoveryCode` in factor proof when the
principal has an enrolled required factor. Disabling TOTP does not remove enrollment; unavailable factor methods fail closed. The result is
`array{subject: Authenticatable, token: IssuedApiToken}`.

The operation runs native eligibility, factor proof, the login pipeline, canonical
principal rechecks, metadata, audit and token issuance without using a web guard
or session. Its adapter must implement `TransactionalApiTokenManager`; principal,
native audit and token writes must use the same connection. Unsupported or split
storage fails closed. Host audit callbacks and domain events follow the outer
source commit. A consumed factor proof stays consumed if a subsequent login stage
rejects, preserving replay protection.

`verifyCredentials()` proves credentials only; it does not replace a complete
authentication operation. Stateful `login()` owns the same native factor and
canonical credential/eligibility checks before session success. Supply `code` or
`recoveryCode` in its optional proof. With an enrolled factor but no proof it
throws `second_factor_required` and retains an opaque continuation in the supplied
session. The existing locked challenge store enforces five-minute expiry, five
attempts and one-use consumption, including across stale session snapshots. No
password is retained. The host can show its factor form when
`hasPendingSecondFactor()` returns true, then call `completeSecondFactor()` with
the proof and the same guard/session. Password changes, disabled principals,
expired/consumed challenges and pipeline identity substitution fail closed.

Native authentication proof storage is mandatory even with all optional delivery/factor methods disabled. The forward proof-storage migration installs the existing challenge shape; historical migrations remain unchanged.

## AuthenticationSessions

```php
public function establishFromProof(#[SensitiveParameter] string $proof, StatefulGuard $guard, Session $session, AuthenticationRequestContext $context, bool $remember = false): Authenticatable;
public function logout(StatefulGuard $guard, Session $session): void;
```

## AuthChallenges

```php
public function consume(AuthFeature $feature, AuthMessageType $messageType, string $recipient, string $purpose, string $secret): Challenge;
public function consumeById(AuthFeature $feature, AuthMessageType $messageType, string $challengeId, string $purpose, string $secret): Challenge;
public function consumeMagicLink(array $data, string $purpose = 'login'): Challenge;
public function requestMagicLink(array $data, ?SubjectReference $subject = null, array $payload = [], ?string $locale = null): array;
public function requestMagicLinkAuthentication(array $data, AuthenticationRequestContext $context, ?string $locale = null): ?array;
public function consumeMagicLinkAuthentication(#[SensitiveParameter] array $data, AuthenticationRequestContext $context): IssuedAuthenticationProof;
public function requestSecurityCode(array $data, ?SubjectReference $subject = null, array $payload = [], ?string $locale = null): array;
public function requestSecurityCodeAuthentication(array $data, AuthenticationRequestContext $context, ?string $locale = null): ?array;
public function proveSecurityCodeAuthentication(#[SensitiveParameter] array $data, AuthenticationRequestContext $context): IssuedAuthenticationProof;
public function verifySecurityCode(array $data): Challenge;
public function verifySecurityCodeAuthentication(#[SensitiveParameter] array $data, StatefulGuard $guard, Session $session, AuthenticationRequestContext $context): Authenticatable;
```

## AuthPasswords

```php
public function requestReset(array $data, ?string $locale = null): void;
public function reset( #[SensitiveParameter] array $data ): void;
public function update( Authenticatable&CanResetPassword $subject, #[SensitiveParameter] array $data, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): void;
```

## AuthEmailVerification

```php
public function verify(Authenticatable&MustVerifyEmail $subject, #[SensitiveParameter] string $token): bool;
```

## AuthInvitations

```php
public function create(array $data, Authenticatable|SystemMutationContext $authority, ?InvitationIssuanceContext $context = null): array;
public function findActive(string $recipient, string $purpose, ?array $types = null, ?string $context = null, Authenticatable|SystemMutationContext|null $authority = null): ?Invitation;
public function paginate(Authenticatable $actor, array $filters = [], int $perPage = 25): LengthAwarePaginator;
public function preview(string $token): Invitation;
public function recordDeliveryOutcome(string $invitationId, string $messageId, InvitationDeliveryStatus $status, CarbonImmutable $occurredAt, ?string $failureCode = null): void;
public function register(array $data, ?Authenticatable $authenticatedRecipient = null): array;
public function resend(Invitation|string $invitation, Authenticatable|SystemMutationContext $authority, ?string $locale = null, ?InvitationIssuanceContext $context = null): array;
public function revoke(Invitation|string $invitation, Authenticatable|SystemMutationContext $authority): Invitation;
```

## AuthUsers

```php
public function create(Authenticatable $actor, #[\SensitiveParameter] array $data): User;
public function deleteOwnAccount(Authenticatable $subject, #[\SensitiveParameter] array $data, StatefulGuard $guard, Session $session, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): bool;
public function delete(Authenticatable|SystemMutationContext $authority, User|string $user): bool;
public function restore(Authenticatable|SystemMutationContext $authority, User|string $user): User;
public function setActive(Authenticatable|SystemMutationContext $authority, User|string $user, #[\SensitiveParameter] array $data): User;
public function updateProfile(Authenticatable $subject, #[\SensitiveParameter] array $data, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): User;
public function update(Authenticatable $actor, User|string $user, #[\SensitiveParameter] array $data): User;
```

## AuthUserReader

```php
public function profile(Authenticatable $subject): User;
public function find(Authenticatable $actor, User|string $user): User;
public function suggest(Authenticatable $actor, string $search, ?int $limit = null): Collection;
```

## AuthClients

```php
public function delete(Authenticatable $actor, AuthClient $client): void;
public function endSession(AuthClientSession $session, string $reason = 'logout'): AuthClientSession;
public function paginate(Authenticatable $actor, int $perPage = 25): LengthAwarePaginator;
public function recordSession(AuthClient $client, string $sessionId, ?Authenticatable $subject = null, ?string $ipAddress = null, ?string $userAgent = null, array $metadata = []): AuthClientSession;
public function setActive(Authenticatable $actor, AuthClient $client, bool $active): AuthClient;
public function find(Authenticatable $actor, AuthClient $client): AuthClient;
public function start(array $data): array;
public function touchSession(string $clientId, string $sessionId): AuthClientSession;
public function update(Authenticatable $actor, AuthClient $client, array $data): AuthClient;
```

## AuthMemberships

```php
public function enroll(Authenticatable|SystemMutationContext $authority, SubjectReference $subject, array $roles = [], array $permissions = []): OwnerMembership;
public function setStatus(Authenticatable|SystemMutationContext $authority, Membership|string $membership, MembershipStatus $status, int $expectedRevision): OwnerMembership;
public function transfer(Authenticatable|SystemMutationContext $authority, Membership|string $membership, string $recipientId, int $expectedRevision): OwnerMembership;
public function assertPrincipalCanBeDisabled(SubjectReference $subject): void;
public function lock(bool $prepare = false): void;
public function find(Authenticatable $actor, Membership|string $membership): OwnerMembership;
public function paginate(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator;
public function revoke(Authenticatable|SystemMutationContext $authority, Membership|string $membership, int $expectedRevision): OwnerMembership;
public function own(Authenticatable $subject): Collection;
```

## AuthAuditReader

```php
public function find(Authenticatable $actor, AuthAudit $audit): AuthAudit;
```

## AuthMaintenance

```php
public function prune(Authenticatable|SystemMutationContext $authority, bool $dryRun = false): array;
```

## AuthTokens

```php
public function create(Authenticatable $subject, array $data): IssuedApiToken;
public function all(Authenticatable $subject): array;
public function revokeAll(Authenticatable $subject): int;
public function revoke(Authenticatable $subject, string $tokenId): bool;
public function rotate( Authenticatable $subject, string $tokenId, array $data, ): IssuedApiToken;
public function update( Authenticatable $subject, string $tokenId, array $data, ): array;
```

Raw `create()` is a token management operation. It reloads the persisted principal
and rechecks configured authentication eligibility and token policy at issuance
and pipeline success boundaries. Native transactional adapters include token and
audit writes in their source transaction. Non-Eloquent custom providers retain
their external freshness contract. Use `loginWithToken()` for complete
credential-based token authentication.

## AuthRoles

```php
public function update(Authenticatable $actor, Role|string $role, array $data): Role;
public function delete(Authenticatable $actor, Role|string $role): bool;
public function duplicate(Authenticatable $actor, Role|string $role, string $name, ?string $displayName = null): Role;
public function addPermissions(Authenticatable $actor, Role|string $role, array $permissionIdentifiers): Role;
public function syncPermissions(Authenticatable $actor, Role|string $role, array $permissionIdentifiers): Role;
public function applyTemplate(Authenticatable $actor, array $data): Role;
public function synchronizeTemplates(Authenticatable $actor): int;
public function syncUserRoles(Authenticatable|SystemMutationContext $authority, Authenticatable|string $user, array $data): Authenticatable;
```

## AuthPermissions

```php
public function createWithRoles(Authenticatable $actor, array $data, array $roleIdentifiers = []): Permission;
public function update(Authenticatable $actor, Permission|string $permission, array $data): Permission;
public function delete(Authenticatable $actor, Permission|string $permission): bool;
public function synchronizeCatalog(Authenticatable $actor): int;
public function syncUserPermissions(Authenticatable|SystemMutationContext $authority, Authenticatable|string $user, array $data): Authenticatable;
public function synchronize(Authenticatable $actor): array;
public function bootstrap(SystemMutationContext $context): array;
```

Catalog synchronization uses the configured Permission model's actual connection.
Template synchronization, template application and combined synchronization/bootstrap
require configured Role and Permission models on the same actual connection and
reject a split before writes. Failed synchronization rolls back that source;
success audits follow its outer commit and are discarded on rollback.

## AuthRbacReader

```php
public function permissionCatalog(Authenticatable $actor, array $data): LengthAwarePaginator;
public function permissionGroups(Authenticatable $actor): Collection;
public function permissionOptions(Authenticatable $actor, ?string $search = null, ?string $group = null, ?int $limit = null): Collection;
public function permissions(Authenticatable $actor, ?string $search = null, ?string $group = null, int $perPage = 25): LengthAwarePaginator;
public function roleCatalog(Authenticatable $actor, array $data): LengthAwarePaginator;
public function roleHierarchy(Authenticatable $actor): array;
public function roleOptions(Authenticatable $actor, ?string $search = null, ?int $limit = null): Collection;
public function roleTemplates(Authenticatable $actor): array;
public function roles(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator;
public function resolvePermissions(Authenticatable $actor, array $identifiers): Collection;
public function resolveRoles(Authenticatable $actor, array $identifiers): Collection;
public function permission(Authenticatable $actor, Permission|string $permission): Permission;
public function analytics(Authenticatable $actor): array;
public function role(Authenticatable $actor, Role|string $role): Role;
public function roleAnalytics(Authenticatable $actor, Role|string $role): array;
public function suggestPermissions(Authenticatable $actor, ?string $search = null, ?string $group = null, ?int $limit = null): Collection;
public function suggestRoles(Authenticatable $actor, ?string $search = null, ?int $limit = null): Collection;
```

## AuthSecondFactor

```php
public function confirmEnrollment( Authenticatable $subject, TotpCredential $credential, #[SensitiveParameter] array $data, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): TotpCredential;
public function verify( Authenticatable $subject, #[SensitiveParameter] array $data ): TotpCredential;
public function revoke(Authenticatable $subject, TotpCredential $credential, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): TotpCredential;
public function state(Authenticatable $subject): array;
public function regenerateRecoveryCodes(Authenticatable $subject, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): GeneratedRecoveryCodes;
public function consumeRecoveryCode( Authenticatable $subject, #[SensitiveParameter] array $data ): RecoveryCode;
public function revokeRecoveryCodes(Authenticatable $subject, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): int;
```

## AuthPasskeys

```php
public function beginAuthentication(?Authenticatable $subject = null, ?OwnerReference $owner = null, ?string $sessionBinding = null, ?AuthenticationRequestContext $context = null): PasskeyCeremonyOptions;
public function beginReauthentication(Authenticatable $subject, AuthenticationRequestContext $context): PasskeyCeremonyOptions;
public function beginRegistration(Authenticatable $subject, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): PasskeyCeremonyOptions;
public function finishAuthentication(#[\SensitiveParameter] array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null): array;
public function finishRegistration(Authenticatable $subject, #[\SensitiveParameter] array $data, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): Passkey;
public function revoke(Authenticatable $subject, Passkey $passkey, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): Passkey;
```

## Explicit social workflows

`AuthSocialAuthentication::beginLogin(provider, context, destination)` returns an authorization URL and redacted intent. Retain intent/context privately in the initiating browser. `completeLogin(provider, intent, context)` returns either `authenticated` with subject/proof, or `registration_required` with a redacted continuation. Only active exact immutable links authenticate; no email matching occurs. Subject-bound `beginReauthentication`/`completeReauthentication` issue social primary proof for `AuthReauthentication::confirm(['socialProof' => ...])`; native MFA remains mandatory.

`AuthSocialLinks::beginLink(subject, provider, recentProof, context)` and `beginReconnect` consume purpose-specific recent grants before redirect. Their matching completions acquire verified SDK claims and perform the native locked mutation. `unlink(subject, identityId, recentProof, context)` enforces ownership and the final usable primary method. Raw `ExternalIdentity` input cannot create a link. Reconnect is explicit and cannot transfer ownership.

`AuthRegistration::registerSocial(continuation, data, context)` and `registerInvitedSocial(invitationToken, continuation, data, context)` create without logging in. Use `requestSocialEmailVerification` / `verifySocialEmail` when provider claims lack mailbox proof. Continuations expire after 300 seconds; replacement local proof retains the original deadline and has bounded attempts/issuance. Profile/extensions remain allowlisted and consumer-mapped.

## Account security and browser authority

`AuthAccountSecurity::state(subject)` projects usable methods without secrets. `AuthPasswords::setInitial` and `revoke` require PasswordChange grants; removal preserves a usable primary. `AuthAccountRecovery::recover(authority, subject, data)` requires separate recovery authority, reason and closed credential selections with complete session/token containment.

`AuthEmailChanges::request(subject, newEmail, recentProof, context)` stages a pending mailbox. Deliver its typed verification token privately; `complete(subject, token, context)` proves and replaces once within 60 minutes. `cancel(subject, changeId)` revokes a pending request. Generic profile updates reject replacement email.

`AuthBrowserSessions::paginate`, `admit`, `revoke`, `revokeOthers` and `revokeAll` manage authoritative browser grants. Enrollment is private to successful native authentication; arbitrary principals/evidence cannot enroll. `AuthRememberCredentials::resume` consumes a rotating per-device selector/secret into native primary proof, followed by normal MFA and browser admission.

`AuthImpersonation::start`, `admit`, `stop` and separately authorized `revoke` manage short-lived grants. `LaravelImpersonation` handles binding/session rotation and temporary guard identity with safe restoration. `AuthExecutionContext::facts` is a bounded read seam for consumer audit attribution and cannot confer queue authority. See [security](security.md) for restrictions.

## Proof-backed completion

Raw-principal `establish` and `establishForPurpose` are removed. Use complete `login` / `loginWithToken`, or optionally compose native verified proof initiation and completion:

```php
$context = new AuthenticationRequestContext(
    guardName: 'web', sessionBinding: $request->session()->getId(),
);
$proof = $authentication->proveCredentials($credentials, $context);
$subject = $sessions->establishFromProof(
    $proof->reveal(), $guard, $request->session(), $context,
);
```

Context is trusted host transport, never credential input. Preserve it from email request to redemption and from passkey/social initiation to completion. Passkey completion returns `subject`, `proof` and native `requestContext`; use that returned context. Social initiation returns `url` and redacted `intent`; retain the intent and context in the initiating browser session, and use `completeLogin` after SDK-managed OAuth state validation. Generic delivery challenges and social identity models cannot authenticate.

For enrolled principals, password, email link/code, ordinary social and non-UV passkeys require the same second-factor continuation. Native verified UV passkeys satisfy MFA. Handle `second_factor_required` with the host factor form, then call `Authentication::completeSecondFactor($factorProof, $guard, $session)`. Final verified authentication proofs/continuations expire after 300 seconds and share five failed factor attempts. Primary email delivery retains its configured digits/fallback digits, TTL and primary attempt limit; those settings do not change final proof/MFA limits. TOTP or recovery follows valid primary proof; recovery is never a primary login method. A custom `AuthenticationAssurancePolicy` can add requirements but cannot disable native enrollment enforcement.

For optional stateless composition, supply a trusted `tokenNamespace` and a cryptographically random `flowNonce` of at least 32 characters to `proveCredentialsForToken`, then call `AuthTokens::authenticateFromProof($proof->reveal(), $token, $context)`. Token operations never inspect browser state. Session and token proofs reject each other's destination and reject changed guard, browser, owner intent, namespace or nonce.

Only `IssuedAuthenticationProof::reveal()` discloses the bearer. Debug output is redacted; JSON/PHP serialization throws. Hooks receive method, subject and bounded operation attributes, never credentials, factor codes, proof bearers or password fingerprints. Exactly one terminal invocation with the original context is required. Native canonical/password/revision/enrollment checks surround consumer hooks.

Successful proof consumption precedes configurable login/token pipelines. A later ordinary pipeline rejection leaves it consumed; explicit outer token rollback restores all transaction-participating proof/token/fact state atomically. Complete browser guard transitions outside host domain transactions.

## Native recent authentication

```php
$context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $request->session()->getId());
$grant = $reauthentication->confirm($subject, ['password' => $password, 'code' => $totp], RecentAuthenticationPurpose::PasswordChange, $context);
$passwords->update($subject, ['password' => $newPassword, 'passwordConfirmation' => $newPassword], $grant->reveal(), $context);
```

`AuthReauthentication::confirm()` accepts exactly one primary (`password`, an opaque `passkeyProof` or `socialProof`) and at most one `code`/`recoveryCode`. Use `AuthPasskeys::beginReauthentication()` and `finishAuthentication()` for a subject-bound passkey receipt; session-login receipts cannot be reused for confirmation. Verified UV supports passwordless principals. Social receipts must come from the same subject’s active immutable link and a connection explicitly supporting reauthentication. TOTP/recovery alone is insufficient.

Confirmation runs outside the principal source transaction. The grant binds the closed `RecentAuthenticationPurpose`, canonical subject, current security revision and trusted guard/session for 300 seconds. The intended mutation consumes it inside its own transaction: rollback restores grant/mutation, while the previously committed factor stays spent. Self-service password/email/deletion, factor enrollment/removal, recovery regeneration and social linking/unlinking/reconnection require the matching grant even through direct PHP calls. Enrollment begin and completion are distinct operations, each accepting an explicit grant; an operation that changes security revision requires a new confirmation for later operations.

`AccountConfirmation::assertConfirmed(subject, AuthenticationEvidence, RecentAuthenticationPurpose)` adds host policy after mandatory native validation. It receives no credential, bearer or password fingerprint and cannot disable validation. Native proof/security-state schema is mandatory; optional method flags do not erase enrollment requirements. `auth.password_confirmed_at` remains presentation only. Separately authorized administration and `SystemMutationContext` keep their existing authority; consumers deliberately orchestrate any human-admin step-up.

## Stateful source boundary

`AuthenticationSessions::assertCanTransition(?Authenticatable $subject = null): void` is the narrow preflight for immediate browser compositions. Call it before native primary verification, OAuth/session-map mutation or SDK work; then use the complete native finalizer. It checks actual configured principal/provider, proof and audit source connections. `login`, `establishFromProof`, pending-factor completion, logout and self-deletion enforce this themselves before their effects. Pure proof issuance and ordinary domain mutations may join the caller transaction. Commit registration before login. Do not wrap self-delete-with-logout in a host transaction.

The rejection is `stateful_transaction_unsupported` with status409. No testing-transaction exception exists. Browser failure cleanup invalidates the session/CSRF and clears partial authentication; native success facts remain on their source commit. Framework guard events and consumer external side effects cannot be un-fired by SQL rollback.

### Canonical email identity adoption

`PrincipalEmailIdentity::normalize(string $email): string` and `key(string $email): string` use exact UTF-8 lowercase/trim semantics without provider-specific rewriting. `PrincipalEmailIdentityAdoption::plan()` returns `missing`, bounded `collisions` (`key`, `subjectIds`), and `ready`. `apply(SystemMutationContext $authority)` returns `updated` and `finalized`; explicit system authorization and drained legacy workers are required. Host-owned DDL remains the host's responsibility.
