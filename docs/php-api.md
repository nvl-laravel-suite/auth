# Native Auth service API

Inject the following families from `Nvl\Auth\Services`. Signatures below reflect source. Parameter array shapes and validation are documented with each implementation. There are no operation aliases.

## Authentication

```php
public function verifyCredentials( #[SensitiveParameter] array $credentials ): Authenticatable;
```

## AuthenticationSessions

```php
public function establishForPurpose(Authenticatable $principal, StatefulGuard $guard, Session $session, AuthenticationPurpose $purpose, AuthenticationRequestContext $requestContext, bool $remember = false): void;
public function logout(StatefulGuard $guard, Session $session): void;
```

## AuthChallenges

```php
public function consume(AuthFeature $feature, AuthMessageType $messageType, string $recipient, string $purpose, string $secret): Challenge;
public function consumeById(AuthFeature $feature, AuthMessageType $messageType, string $challengeId, string $purpose, string $secret): Challenge;
public function consumeMagicLink(array $data, string $purpose = 'login'): Challenge;
public function requestMagicLink(array $data, ?SubjectReference $subject = null, array $payload = [], ?string $locale = null): array;
public function requestMagicLinkAuthentication(array $data, ?string $locale = null): ?array;
public function requestSecurityCode(array $data, ?SubjectReference $subject = null, array $payload = [], ?string $locale = null): array;
public function requestSecurityCodeAuthentication(array $data, ?string $locale = null): ?array;
public function verifySecurityCode(array $data): Challenge;
public function verifySecurityCodeAuthentication(array $data, StatefulGuard $guard, Session $session): Challenge;
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
public function all(Authenticatable $subject): array;
public function revokeAll(Authenticatable $subject): int;
public function revoke(Authenticatable $subject, string $tokenId): bool;
public function rotate( Authenticatable $subject, string $tokenId, array $data, ): IssuedApiToken;
public function update( Authenticatable $subject, string $tokenId, array $data, ): array;
```

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
public function beginRegistration(Authenticatable $subject): PasskeyCeremonyOptions;
public function finishAuthentication( array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null, ): array;
public function finishRegistration( Authenticatable $subject, array $data, ): Passkey;
public function revoke(Authenticatable $subject, Passkey $passkey): Passkey;
```

## AuthSocialIdentities

```php
public function completeAuthorization(string $provider, ?Authenticatable $subject = null): SocialIdentity;
public function link(Authenticatable $subject, ExternalIdentity $identity): SocialIdentity;
public function revoke(Authenticatable $subject, SocialIdentity $identity): SocialIdentity;
```

`AuthenticationSessions::establishForPurpose` is an internal orchestration seam for proved passwordless/social authentication. Its explicit AuthenticationPurpose and bounded AuthenticationRequestContext select the correct eligibility policy once; it is not an HTTP input selector.
