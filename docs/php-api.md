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
public function update( Authenticatable&CanResetPassword $subject, #[SensitiveParameter] array $data ): void;
```

## AuthEmailVerification

```php
public function verify(Authenticatable&MustVerifyEmail $subject): bool;
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
public function revoke(Invitation|string $invitation, Authenticatable $actor): Invitation;
```

## AuthUsers

```php
public function create(Authenticatable $actor, array $data): User;
public function deleteOwnAccount(Authenticatable $subject, array $data, StatefulGuard $guard, Session $session): bool;
public function delete(Authenticatable|SystemMutationContext $authority, User|string $user): bool;
public function restore(Authenticatable|SystemMutationContext $authority, User|string $user): User;
public function setActive(Authenticatable|SystemMutationContext $authority, User|string $user, array $data): User;
public function updateProfile(Authenticatable $subject, array $data): User;
public function update(Authenticatable $actor, User|string $user, array $data): User;
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
public function confirmEnrollment( Authenticatable $subject, TotpCredential $credential, #[SensitiveParameter] array $data, ): TotpCredential;
public function verify( Authenticatable $subject, #[SensitiveParameter] array $data, ): TotpCredential;
public function revoke( Authenticatable $subject, TotpCredential $credential, ): TotpCredential;
public function state(Authenticatable $subject): array;
public function regenerateRecoveryCodes(Authenticatable $subject): GeneratedRecoveryCodes;
public function consumeRecoveryCode( Authenticatable $subject, #[SensitiveParameter] array $data, ): RecoveryCode;
public function revokeRecoveryCodes(Authenticatable $subject): int;
```

## AuthPasskeys

```php
public function beginAuthentication(?Authenticatable $subject = null, ?OwnerReference $owner = null, ?string $sessionBinding = null, ?AuthenticationRequestContext $context = null): PasskeyCeremonyOptions;
public function beginRegistration(Authenticatable $subject): PasskeyCeremonyOptions;
public function finishAuthentication( array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null, ): array;
public function finishRegistration( Authenticatable $subject, array $data, ): Passkey;
public function revoke(Authenticatable $subject, Passkey $passkey): Passkey;
```

## AuthSocialIdentities

```php
public function startAuthentication(string $provider, AuthenticationRequestContext $context): array;
public function finishAuthentication(string $provider, #[SensitiveParameter] string $intent, AuthenticationRequestContext $context): IssuedAuthenticationProof;
public function completeAuthorization(string $provider, ?Authenticatable $subject = null): SocialIdentity;
public function link(Authenticatable $subject, ExternalIdentity $identity): SocialIdentity;
public function revoke(Authenticatable $subject, SocialIdentity $identity): SocialIdentity;
```

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

Context is trusted host transport, never credential input. Preserve it from email request to redemption and from passkey/social initiation to completion. Passkey completion returns `subject`, `proof` and native `requestContext`; use that returned context. Social initiation returns `url` and redacted `intent`; retain the intent and context in the initiating browser session, and use `finishAuthentication` after SDK-managed OAuth state validation. Generic delivery challenges and social identity models cannot authenticate.

For enrolled principals, password, email link/code, ordinary social and non-UV passkeys require the same second-factor continuation. Native verified UV passkeys satisfy MFA. Handle `second_factor_required` with the host factor form, then call `Authentication::completeSecondFactor($factorProof, $guard, $session)`. Final verified authentication proofs/continuations expire after 300 seconds and share five failed factor attempts. Primary email delivery retains its configured digits/fallback digits, TTL and primary attempt limit; those settings do not change final proof/MFA limits. TOTP or recovery follows valid primary proof; recovery is never a primary login method. A custom `AuthenticationAssurancePolicy` can add requirements but cannot disable native enrollment enforcement.

For optional stateless composition, supply a trusted `tokenNamespace` and a cryptographically random `flowNonce` of at least 32 characters to `proveCredentialsForToken`, then call `AuthTokens::authenticateFromProof($proof->reveal(), $token, $context)`. Token operations never inspect browser state. Session and token proofs reject each other's destination and reject changed guard, browser, owner intent, namespace or nonce.

Only `IssuedAuthenticationProof::reveal()` discloses the bearer. Debug output is redacted; JSON/PHP serialization throws. Hooks receive method, subject and bounded operation attributes, never credentials, factor codes, proof bearers or password fingerprints. Exactly one terminal invocation with the original context is required. Native canonical/password/revision/enrollment checks surround consumer hooks.

Successful proof consumption precedes configurable login/token pipelines. A later ordinary pipeline rejection leaves it consumed; explicit outer token rollback restores all transaction-participating proof/token/fact state atomically. Complete browser guard transitions outside host domain transactions.
