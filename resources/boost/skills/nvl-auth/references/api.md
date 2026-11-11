# Public API: nvl/auth

Generated from the package public contract. Use this reference to confirm fully qualified names, parameter order, defaults, native array shapes and return types. Read [usage](usage.md) for policy and operation semantics; declarations alone never grant authority.

Search for the relevant fully qualified service or contract and read only its matching symbol sections; this is a lookup catalog, not an instruction to load every declaration. `resolved` annotations expand imported aliases and domain type shapes. Framework inheritance and host-authored extensions remain outside this package contract.

## Symbols

- `Nvl\Auth\Adapters\Laravel\LaravelImpersonation`
- `Nvl\Auth\Adapters\Laravel\LaravelSessionAdmission`
- `Nvl\Auth\Adapters\Laravel\ManagedSessionGuard`
- `Nvl\Auth\Adapters\Socialite\Contracts\SocialiteDriverFactory`
- `Nvl\Auth\Adapters\Socialite\SocialiteProviderFactory`
- `Nvl\Auth\Contracts\AccountAuthenticationPolicy`
- `Nvl\Auth\Contracts\AccountConfirmation`
- `Nvl\Auth\Contracts\ApiTokenAbilityProvider`
- `Nvl\Auth\Contracts\ApiTokenManager`
- `Nvl\Auth\Contracts\AuthAuditContextProvider`
- `Nvl\Auth\Contracts\AuthAuditRecorder`
- `Nvl\Auth\Contracts\AuthIdentifierResolver`
- `Nvl\Auth\Contracts\AuthManagementAccess`
- `Nvl\Auth\Contracts\AuthPipelineStage`
- `Nvl\Auth\Contracts\AuthSubjectResolver`
- `Nvl\Auth\Contracts\AuthenticationAssurancePolicy`
- `Nvl\Auth\Contracts\AuthenticationEligibility`
- `Nvl\Auth\Contracts\ImpersonationAccess`
- `Nvl\Auth\Contracts\InvitationSubjectResolver`
- `Nvl\Auth\Contracts\OwnerBoundApiTokenManager`
- `Nvl\Auth\Contracts\PasskeyCeremony`
- `Nvl\Auth\Contracts\PasswordUpdater`
- `Nvl\Auth\Contracts\PermissionCatalogProvider`
- `Nvl\Auth\Contracts\PrincipalAttributeMapper`
- `Nvl\Auth\Contracts\PrincipalExtensionMapper`
- `Nvl\Auth\Contracts\PrincipalSessionContainment`
- `Nvl\Auth\Contracts\RbacPrincipalAccess`
- `Nvl\Auth\Contracts\RegistrationAdmission`
- `Nvl\Auth\Contracts\RoleTemplateProvider`
- `Nvl\Auth\Contracts\SecurityTokenContainment`
- `Nvl\Auth\Contracts\SocialIdentityProvider`
- `Nvl\Auth\Contracts\SocialIdentityProviderFactory`
- `Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder`
- `Nvl\Auth\Contracts\SystemMutationAccess`
- `Nvl\Auth\Contracts\TransactionalApiTokenManager`
- `Nvl\Auth\Database\Factories\AuthAuditFactory`
- `Nvl\Auth\Database\Factories\AuthClientFactory`
- `Nvl\Auth\Database\Factories\AuthClientSessionFactory`
- `Nvl\Auth\Database\Factories\ChallengeFactory`
- `Nvl\Auth\Database\Factories\InvitationFactory`
- `Nvl\Auth\Database\Factories\OwnerMembershipFactory`
- `Nvl\Auth\Database\Factories\PasskeyFactory`
- `Nvl\Auth\Database\Factories\PermissionFactory`
- `Nvl\Auth\Database\Factories\PersonalAccessTokenFactory`
- `Nvl\Auth\Database\Factories\RecoveryCodeFactory`
- `Nvl\Auth\Database\Factories\RoleFactory`
- `Nvl\Auth\Database\Factories\SocialIdentityFactory`
- `Nvl\Auth\Database\Factories\TotpCredentialFactory`
- `Nvl\Auth\Database\Factories\UserFactory`
- `Nvl\Auth\Enums\AuthFeature`
- `Nvl\Auth\Enums\AuthMessageType`
- `Nvl\Auth\Enums\AuthResponseCode`
- `Nvl\Auth\Enums\AuthenticationDestination`
- `Nvl\Auth\Enums\AuthenticationMethod`
- `Nvl\Auth\Enums\AuthenticationPurpose`
- `Nvl\Auth\Enums\FeatureOperation`
- `Nvl\Auth\Enums\InvitationDeliveryStatus`
- `Nvl\Auth\Enums\MembershipStatus`
- `Nvl\Auth\Enums\OwnerAuthenticationPurpose`
- `Nvl\Auth\Enums\PrincipalAttribute`
- `Nvl\Auth\Enums\PrincipalMutation`
- `Nvl\Auth\Enums\RecentAuthenticationPurpose`
- `Nvl\Auth\Enums\RegistrationMethod`
- `Nvl\Auth\Enums\RegistrationMode`
- `Nvl\Auth\Enums\SocialIntentPurpose`
- `Nvl\Auth\Enums\UserBulkOperation`
- `Nvl\Auth\Events\AccountSecurityChanged`
- `Nvl\Auth\Events\AuthAuditRecorded`
- `Nvl\Auth\Events\AuthDeliveryRequested`
- `Nvl\Auth\Events\AuthenticationAttempted`
- `Nvl\Auth\Events\AuthenticationRejected`
- `Nvl\Auth\Events\ImpersonationChanged`
- `Nvl\Auth\Events\InvitationAccepted`
- `Nvl\Auth\Events\PrincipalChanged`
- `Nvl\Auth\Events\PrincipalRegistered`
- `Nvl\Auth\Events\RbacAssignmentChanged`
- `Nvl\Auth\Events\RbacChanged`
- `Nvl\Auth\Events\UserAuthenticated`
- `Nvl\Auth\Events\UserLoggedOut`
- `Nvl\Auth\Exceptions\AuthException`
- `Nvl\Auth\Models\AuthAudit`
- `Nvl\Auth\Models\AuthClient`
- `Nvl\Auth\Models\AuthClientSession`
- `Nvl\Auth\Models\BrowserSession`
- `Nvl\Auth\Models\Challenge`
- `Nvl\Auth\Models\Impersonation`
- `Nvl\Auth\Models\Invitation`
- `Nvl\Auth\Models\Membership`
- `Nvl\Auth\Models\OwnerMembership`
- `Nvl\Auth\Models\Passkey`
- `Nvl\Auth\Models\PendingEmailChange`
- `Nvl\Auth\Models\Permission`
- `Nvl\Auth\Models\PersonalAccessToken`
- `Nvl\Auth\Models\RecoveryCode`
- `Nvl\Auth\Models\RememberCredential`
- `Nvl\Auth\Models\Role`
- `Nvl\Auth\Models\SocialIdentity`
- `Nvl\Auth\Models\TotpCredential`
- `Nvl\Auth\Models\User`
- `Nvl\Auth\Ownership\AuthOwnerAccess`
- `Nvl\Auth\Results\GeneratedRecoveryCodes`
- `Nvl\Auth\Results\IssuedApiToken`
- `Nvl\Auth\Results\TotpEnrollment`
- `Nvl\Auth\Services\AuthAccountRecovery`
- `Nvl\Auth\Services\AuthAccountSecurity`
- `Nvl\Auth\Services\AuthAuditReader`
- `Nvl\Auth\Services\AuthBrowserSessions`
- `Nvl\Auth\Services\AuthChallenges`
- `Nvl\Auth\Services\AuthClients`
- `Nvl\Auth\Services\AuthEmailChanges`
- `Nvl\Auth\Services\AuthEmailVerification`
- `Nvl\Auth\Services\AuthExecutionContext`
- `Nvl\Auth\Services\AuthImpersonation`
- `Nvl\Auth\Services\AuthInvitations`
- `Nvl\Auth\Services\AuthMaintenance`
- `Nvl\Auth\Services\AuthMemberships`
- `Nvl\Auth\Services\AuthOwnerAdmission`
- `Nvl\Auth\Services\AuthPasskeys`
- `Nvl\Auth\Services\AuthPasswords`
- `Nvl\Auth\Services\AuthPermissions`
- `Nvl\Auth\Services\AuthRbacReader`
- `Nvl\Auth\Services\AuthReauthentication`
- `Nvl\Auth\Services\AuthRegistration`
- `Nvl\Auth\Services\AuthRememberCredentials`
- `Nvl\Auth\Services\AuthRoles`
- `Nvl\Auth\Services\AuthSecondFactor`
- `Nvl\Auth\Services\AuthSocialAuthentication`
- `Nvl\Auth\Services\AuthSocialLinks`
- `Nvl\Auth\Services\AuthTokens`
- `Nvl\Auth\Services\AuthUserReader`
- `Nvl\Auth\Services\AuthUsers`
- `Nvl\Auth\Services\Authentication`
- `Nvl\Auth\Services\AuthenticationProofs`
- `Nvl\Auth\Services\AuthenticationSessions`
- `Nvl\Auth\Services\EnrolledFactorAssurancePolicy`
- `Nvl\Auth\Services\FeatureGate`
- `Nvl\Auth\Services\OwnerAuthenticationIntents`
- `Nvl\Auth\Services\PrincipalEmailIdentity`
- `Nvl\Auth\Services\PrincipalEmailIdentityAdoption`
- `Nvl\Auth\Services\SocialProviderRegistry`
- `Nvl\Auth\Services\UsableAccountAuthenticationPolicy`
- `Nvl\Auth\ValueObjects\AuthDeliveryRequest`
- `Nvl\Auth\ValueObjects\AuthEventContext`
- `Nvl\Auth\ValueObjects\AuthPipelineContext`
- `Nvl\Auth\ValueObjects\AuthenticationEvidence`
- `Nvl\Auth\ValueObjects\AuthenticationRequestContext`
- `Nvl\Auth\ValueObjects\ExternalIdentity`
- `Nvl\Auth\ValueObjects\InvitationIssuanceContext`
- `Nvl\Auth\ValueObjects\IssuedAuthenticationProof`
- `Nvl\Auth\ValueObjects\IssuedRecentAuthentication`
- `Nvl\Auth\ValueObjects\IssuedSocialIntent`
- `Nvl\Auth\ValueObjects\IssuedSocialRegistration`
- `Nvl\Auth\ValueObjects\PasskeyAssertion`
- `Nvl\Auth\ValueObjects\PasskeyCeremonyOptions`
- `Nvl\Auth\ValueObjects\PasskeyCredential`
- `Nvl\Auth\ValueObjects\PasskeyRegistration`
- `Nvl\Auth\ValueObjects\RoleTemplate`
- `Nvl\Auth\ValueObjects\SubjectReference`
- `Nvl\Auth\ValueObjects\SystemMutationContext`

## Nvl\Auth\Adapters\Laravel\LaravelImpersonation

```text
final readonly class Nvl\Auth\Adapters\Laravel\LaravelImpersonation
public function __construct(Nvl\Auth\Services\AuthExecutionContext $execution, Nvl\Auth\Services\AuthenticationSessions $transitions, Illuminate\Auth\AuthManager $auth, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalEligibility $eligibility, Nvl\Auth\Services\AuthImpersonation $grants, Nvl\Auth\Services\AuthBrowserSessions $browsers, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\AuthIdentityChallenges $challenges): mixed
public function run(Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, string $guardName, string $impersonationId, Closure $callback): mixed
@template TResult
@param Closure(): TResult $callback
@return TResult
template Nvl\Auth\Adapters\Laravel\LaravelImpersonation::TResult
public function start(Illuminate\Contracts\Auth\Authenticatable $target, #[SensitiveParameter()] string $recentProof, array $data, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, string $guardName): Nvl\Auth\Models\Impersonation
@param array<string, mixed> $data
public function stop(string $impersonationId, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, string $guardName): Nvl\Auth\Models\Impersonation
```

## Nvl\Auth\Adapters\Laravel\LaravelSessionAdmission

```text
final readonly class Nvl\Auth\Adapters\Laravel\LaravelSessionAdmission
public function __construct(Nvl\Auth\Services\AuthBrowserSessions $sessions, Nvl\Auth\Services\AuthenticationSessions $transitions, Illuminate\Auth\AuthManager $auth): mixed
public function admit(Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, string $guardName): void
```

## Nvl\Auth\Adapters\Laravel\ManagedSessionGuard

```text
final class Nvl\Auth\Adapters\Laravel\ManagedSessionGuard extends Illuminate\Auth\SessionGuard
public function __debugInfo(): array
@return array{guard: string, authenticated: bool}
public static function assertCookieConfiguration(): void
public function getRecallerName(): string
public function login(Illuminate\Contracts\Auth\Authenticatable $user, mixed $remember=false): void
public function logout(): void
public function setRequest(Symfony\Component\HttpFoundation\Request $request): static
public function user(): ?Illuminate\Contracts\Auth\Authenticatable
```

## Nvl\Auth\Adapters\Socialite\Contracts\SocialiteDriverFactory

```text
interface Nvl\Auth\Adapters\Socialite\Contracts\SocialiteDriverFactory
public abstract function make(string $connection): Laravel\Socialite\Contracts\Provider
```

## Nvl\Auth\Adapters\Socialite\SocialiteProviderFactory

```text
final readonly class Nvl\Auth\Adapters\Socialite\SocialiteProviderFactory implements Nvl\Auth\Contracts\SocialIdentityProviderFactory
public function __construct(Nvl\Auth\Services\AuthConfiguration $configuration, Illuminate\Contracts\Container\Container $container): mixed
public function make(string $provider): Nvl\Auth\Contracts\SocialIdentityProvider
```

## Nvl\Auth\Contracts\AccountAuthenticationPolicy

```text
interface Nvl\Auth\Contracts\AccountAuthenticationPolicy
public abstract function assertRemovalAllowed(Illuminate\Contracts\Auth\Authenticatable $subject, string $kind, string $credentialId): void
```

## Nvl\Auth\Contracts\AccountConfirmation

```text
interface Nvl\Auth\Contracts\AccountConfirmation
public abstract function assertConfirmed(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\ValueObjects\AuthenticationEvidence $evidence, Nvl\Auth\Enums\RecentAuthenticationPurpose $purpose): void
```

## Nvl\Auth\Contracts\ApiTokenAbilityProvider

```text
interface Nvl\Auth\Contracts\ApiTokenAbilityProvider
public abstract function abilities(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return list<string>
```

## Nvl\Auth\Contracts\ApiTokenManager

```text
interface Nvl\Auth\Contracts\ApiTokenManager
public abstract function create(Illuminate\Contracts\Auth\Authenticatable $subject, array $data): Nvl\Auth\Results\IssuedApiToken
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
public abstract function list(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}>
resolved @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}>
public abstract function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId): bool
public abstract function revokeAll(Illuminate\Contracts\Auth\Authenticatable $subject): int
public abstract function rotate(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): Nvl\Auth\Results\IssuedApiToken
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
public abstract function update(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): array
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
@return array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}
resolved @return array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}
```

## Nvl\Auth\Contracts\AuthAuditContextProvider

```text
interface Nvl\Auth\Contracts\AuthAuditContextProvider
public abstract function ipAddress(): ?string
public abstract function requestId(): ?string
public abstract function userAgent(): ?string
```

## Nvl\Auth\Contracts\AuthAuditRecorder

```text
interface Nvl\Auth\Contracts\AuthAuditRecorder
public abstract function record(string $action, string $outcome="success", ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, ?Illuminate\Contracts\Auth\Authenticatable $actor=null, ?string $clientId=null, array $metadata=[]): ?object
@param array<string, mixed> $metadata
```

## Nvl\Auth\Contracts\AuthIdentifierResolver

```text
interface Nvl\Auth\Contracts\AuthIdentifierResolver
public abstract function resolve(string $identifierName, string $identifier): ?Illuminate\Contracts\Auth\Authenticatable
```

## Nvl\Auth\Contracts\AuthManagementAccess

```text
interface Nvl\Auth\Contracts\AuthManagementAccess
public abstract function allows(Illuminate\Contracts\Auth\Authenticatable $actor, string $ability, mixed $target=null): bool
```

## Nvl\Auth\Contracts\AuthPipelineStage

```text
interface Nvl\Auth\Contracts\AuthPipelineStage
public abstract function handle(Nvl\Auth\ValueObjects\AuthPipelineContext $context, Closure $next): mixed
```

## Nvl\Auth\Contracts\AuthSubjectResolver

```text
interface Nvl\Auth\Contracts\AuthSubjectResolver
public abstract function resolve(Nvl\Auth\ValueObjects\SubjectReference $reference): ?Illuminate\Contracts\Auth\Authenticatable
```

## Nvl\Auth\Contracts\AuthenticationAssurancePolicy

```text
interface Nvl\Auth\Contracts\AuthenticationAssurancePolicy
public abstract function assertSatisfied(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\ValueObjects\AuthenticationEvidence $evidence, Nvl\Auth\Enums\AuthenticationPurpose $purpose): void
```

## Nvl\Auth\Contracts\AuthenticationEligibility

```text
interface Nvl\Auth\Contracts\AuthenticationEligibility
public abstract function assertEligible(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\Enums\AuthenticationPurpose $purpose): void
```

## Nvl\Auth\Contracts\ImpersonationAccess

```text
interface Nvl\Auth\Contracts\ImpersonationAccess
public abstract function assertAllowed(Illuminate\Contracts\Auth\Authenticatable $actor, Illuminate\Contracts\Auth\Authenticatable $target, ?Nvl\Support\Ownership\ValueObjects\OwnerReference $owner): void
```

## Nvl\Auth\Contracts\InvitationSubjectResolver

```text
interface Nvl\Auth\Contracts\InvitationSubjectResolver
public abstract function resolve(Nvl\Auth\Models\Invitation $invitation, #[SensitiveParameter()] array $input): Illuminate\Contracts\Auth\Authenticatable
@param array<string, mixed> $input
```

## Nvl\Auth\Contracts\OwnerBoundApiTokenManager

```text
interface Nvl\Auth\Contracts\OwnerBoundApiTokenManager
public abstract function ownerForToken(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId): ?Nvl\Support\Ownership\ValueObjects\OwnerReference
```

## Nvl\Auth\Contracts\PasskeyCeremony

```text
interface Nvl\Auth\Contracts\PasskeyCeremony
public abstract function beginAuthentication(?Nvl\Auth\ValueObjects\SubjectReference $subject, array $allowedCredentialIds): Nvl\Auth\ValueObjects\PasskeyCeremonyOptions
@param list<string> $allowedCredentialIds
public abstract function beginRegistration(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\ValueObjects\SubjectReference $reference, array $excludedCredentialIds): Nvl\Auth\ValueObjects\PasskeyCeremonyOptions
@param list<string> $excludedCredentialIds
public abstract function credentialId(array $response): string
@param array<string, mixed> $response
public abstract function finishAuthentication(array $state, array $response, Nvl\Auth\ValueObjects\PasskeyCredential $credential): Nvl\Auth\ValueObjects\PasskeyAssertion
@param array<string, mixed> $state
@param array<string, mixed> $response
public abstract function finishRegistration(Nvl\Auth\ValueObjects\SubjectReference $subject, array $state, array $response): Nvl\Auth\ValueObjects\PasskeyRegistration
@param array<string, mixed> $state
@param array<string, mixed> $response
```

## Nvl\Auth\Contracts\PasswordUpdater

```text
interface Nvl\Auth\Contracts\PasswordUpdater
public abstract function update(Illuminate\Contracts\Auth\CanResetPassword $subject, #[SensitiveParameter()] string $password): void
```

## Nvl\Auth\Contracts\PermissionCatalogProvider

```text
interface Nvl\Auth\Contracts\PermissionCatalogProvider
public abstract function permissions(): array
@return list<string>
```

## Nvl\Auth\Contracts\PrincipalAttributeMapper

```text
interface Nvl\Auth\Contracts\PrincipalAttributeMapper
public abstract function column(Nvl\Auth\Enums\PrincipalAttribute $attribute): string
public abstract function identifier(Nvl\Auth\Models\User $principal): string
public abstract function identifierColumn(string $configuredIdentifier): string
public abstract function map(array $canonicalAttributes): array
@param array<string, mixed> $canonicalAttributes
@return array<string, mixed>
public abstract function value(Nvl\Auth\Models\User $principal, Nvl\Auth\Enums\PrincipalAttribute $attribute): mixed
```

## Nvl\Auth\Contracts\PrincipalExtensionMapper

```text
interface Nvl\Auth\Contracts\PrincipalExtensionMapper
public abstract function validateAndMap(Nvl\Auth\Enums\PrincipalMutation $mutation, #[SensitiveParameter()] array $extensions, ?Nvl\Auth\Models\User $principal=null): array
@param array<string, mixed> $extensions
@return array<string, mixed>
```

## Nvl\Auth\Contracts\PrincipalSessionContainment

```text
interface Nvl\Auth\Contracts\PrincipalSessionContainment
public abstract function contain(Illuminate\Contracts\Auth\Authenticatable $principal, string $operation, ?Nvl\Auth\ValueObjects\SystemMutationContext $context=null): void
```

## Nvl\Auth\Contracts\RbacPrincipalAccess

```text
interface Nvl\Auth\Contracts\RbacPrincipalAccess
public abstract function assign(Illuminate\Contracts\Auth\Authenticatable $principal, array $roles, array $permissions): void
@param list<string> $roles
@param list<string> $permissions
public abstract function connectionName(Illuminate\Contracts\Auth\Authenticatable $principal): ?string
public abstract function find(Illuminate\Contracts\Auth\Authenticatable|string $principal): Illuminate\Contracts\Auth\Authenticatable
public abstract function identifier(Illuminate\Contracts\Auth\Authenticatable $principal): string
public abstract function refresh(Illuminate\Contracts\Auth\Authenticatable $principal, array $relations=[]): Illuminate\Contracts\Auth\Authenticatable
@param list<string> $relations
public abstract function syncPermissions(Illuminate\Contracts\Auth\Authenticatable $principal, array $permissions): void
@param list<string> $permissions
public abstract function syncRoles(Illuminate\Contracts\Auth\Authenticatable $principal, array $roles): void
@param list<string> $roles
```

## Nvl\Auth\Contracts\RegistrationAdmission

```text
interface Nvl\Auth\Contracts\RegistrationAdmission
public abstract function assertAllowed(Nvl\Auth\Enums\RegistrationMethod $method, string $normalizedEmail, array $validatedExtensions): void
@param array<string, mixed> $validatedExtensions
```

## Nvl\Auth\Contracts\RoleTemplateProvider

```text
interface Nvl\Auth\Contracts\RoleTemplateProvider
public abstract function roles(): array
@return list<RoleTemplate>
resolved @return list<Nvl\Auth\ValueObjects\RoleTemplate>
```

## Nvl\Auth\Contracts\SecurityTokenContainment

```text
interface Nvl\Auth\Contracts\SecurityTokenContainment extends Nvl\Auth\Contracts\TransactionalApiTokenManager
public abstract function connection(Illuminate\Contracts\Auth\Authenticatable $subject): Illuminate\Database\Connection
public abstract function create(Illuminate\Contracts\Auth\Authenticatable $subject, array $data): Nvl\Auth\Results\IssuedApiToken
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
public abstract function list(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}>
resolved @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}>
public abstract function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId): bool
public abstract function revokeAll(Illuminate\Contracts\Auth\Authenticatable $subject): int
public abstract function revokeForSecurity(Illuminate\Contracts\Auth\Authenticatable $subject): int
public abstract function rotate(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): Nvl\Auth\Results\IssuedApiToken
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
public abstract function update(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): array
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
@return array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}
resolved @return array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}
```

## Nvl\Auth\Contracts\SocialIdentityProvider

```text
interface Nvl\Auth\Contracts\SocialIdentityProvider
public abstract function redirectUrl(string $provider, ?string $callbackUrl, array $scopes, array $parameters): string
@param list<string> $scopes
@param array<string, scalar> $parameters
public abstract function user(string $provider, ?string $callbackUrl): Nvl\Auth\ValueObjects\ExternalIdentity
```

## Nvl\Auth\Contracts\SocialIdentityProviderFactory

```text
interface Nvl\Auth\Contracts\SocialIdentityProviderFactory
public abstract function make(string $provider): Nvl\Auth\Contracts\SocialIdentityProvider
```

## Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder

```text
interface Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder
public abstract function record(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): void
```

## Nvl\Auth\Contracts\SystemMutationAccess

```text
interface Nvl\Auth\Contracts\SystemMutationAccess
public abstract function allows(Nvl\Auth\ValueObjects\SystemMutationContext $context, string $ability, mixed $target=null): bool
```

## Nvl\Auth\Contracts\TransactionalApiTokenManager

```text
interface Nvl\Auth\Contracts\TransactionalApiTokenManager extends Nvl\Auth\Contracts\ApiTokenManager
public abstract function connection(Illuminate\Contracts\Auth\Authenticatable $subject): Illuminate\Database\Connection
public abstract function create(Illuminate\Contracts\Auth\Authenticatable $subject, array $data): Nvl\Auth\Results\IssuedApiToken
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
public abstract function list(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}>
resolved @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}>
public abstract function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId): bool
public abstract function revokeAll(Illuminate\Contracts\Auth\Authenticatable $subject): int
public abstract function rotate(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): Nvl\Auth\Results\IssuedApiToken
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
public abstract function update(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): array
@param array{name: string, abilities: list<string>, expiresAt: (CarbonImmutable | null)} $data
resolved @param array{name: string, abilities: list<string>, expiresAt: (Carbon\CarbonImmutable | null)} $data
@return array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}
resolved @return array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}
```

## Nvl\Auth\Database\Factories\AuthAuditFactory

```text
final class Nvl\Auth\Database\Factories\AuthAuditFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<AuthAudit>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\AuthAudit>
public function definition(): array
@return array<model-property<AuthAudit>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\AuthAudit>, mixed>
```

## Nvl\Auth\Database\Factories\AuthClientFactory

```text
final class Nvl\Auth\Database\Factories\AuthClientFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<AuthClient>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\AuthClient>
public function definition(): array
@return array<model-property<AuthClient>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\AuthClient>, mixed>
```

## Nvl\Auth\Database\Factories\AuthClientSessionFactory

```text
final class Nvl\Auth\Database\Factories\AuthClientSessionFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<AuthClientSession>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\AuthClientSession>
public function definition(): array
@return array<model-property<AuthClientSession>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\AuthClientSession>, mixed>
```

## Nvl\Auth\Database\Factories\ChallengeFactory

```text
final class Nvl\Auth\Database\Factories\ChallengeFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<Challenge>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\Challenge>
public function definition(): array
@return array<model-property<Challenge>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\Challenge>, mixed>
```

## Nvl\Auth\Database\Factories\InvitationFactory

```text
final class Nvl\Auth\Database\Factories\InvitationFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<Invitation>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\Invitation>
public function definition(): array
@return array<model-property<Invitation>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\Invitation>, mixed>
```

## Nvl\Auth\Database\Factories\OwnerMembershipFactory

```text
final class Nvl\Auth\Database\Factories\OwnerMembershipFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<OwnerMembership>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\OwnerMembership>
public function definition(): array
@return array<model-property<OwnerMembership>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\OwnerMembership>, mixed>
public function modelName(): string
@return class-string<OwnerMembership>
resolved @return class-string<Nvl\Auth\Models\OwnerMembership>
```

## Nvl\Auth\Database\Factories\PasskeyFactory

```text
final class Nvl\Auth\Database\Factories\PasskeyFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<Passkey>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\Passkey>
public function definition(): array
@return array<model-property<Passkey>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\Passkey>, mixed>
public function forSubject(Nvl\Auth\Models\User $subject): static
```

## Nvl\Auth\Database\Factories\PermissionFactory

```text
final class Nvl\Auth\Database\Factories\PermissionFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<Permission>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\Permission>
public function definition(): array
@return array<model-property<Permission>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\Permission>, mixed>
```

## Nvl\Auth\Database\Factories\PersonalAccessTokenFactory

```text
final class Nvl\Auth\Database\Factories\PersonalAccessTokenFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<PersonalAccessToken>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\PersonalAccessToken>
public function definition(): array
@return array<model-property<PersonalAccessToken>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\PersonalAccessToken>, mixed>
```

## Nvl\Auth\Database\Factories\RecoveryCodeFactory

```text
final class Nvl\Auth\Database\Factories\RecoveryCodeFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<RecoveryCode>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\RecoveryCode>
public function definition(): array
@return array<model-property<RecoveryCode>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\RecoveryCode>, mixed>
public function forSubject(Nvl\Auth\Models\User $subject): static
```

## Nvl\Auth\Database\Factories\RoleFactory

```text
final class Nvl\Auth\Database\Factories\RoleFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<Role>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\Role>
public function definition(): array
@return array<model-property<Role>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\Role>, mixed>
```

## Nvl\Auth\Database\Factories\SocialIdentityFactory

```text
final class Nvl\Auth\Database\Factories\SocialIdentityFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<SocialIdentity>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\SocialIdentity>
public function definition(): array
@return array<model-property<SocialIdentity>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\SocialIdentity>, mixed>
public function forSubject(Nvl\Auth\Models\User $subject): static
```

## Nvl\Auth\Database\Factories\TotpCredentialFactory

```text
final class Nvl\Auth\Database\Factories\TotpCredentialFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<TotpCredential>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\TotpCredential>
public function definition(): array
@return array<model-property<TotpCredential>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\TotpCredential>, mixed>
public function forSubject(Nvl\Auth\Models\User $subject): static
```

## Nvl\Auth\Database\Factories\UserFactory

```text
final class Nvl\Auth\Database\Factories\UserFactory extends Illuminate\Database\Eloquent\Factories\Factory
@extends Factory<User>
resolved @extends Illuminate\Database\Eloquent\Factories\Factory<Nvl\Auth\Models\User>
public function configure(): static
public function definition(): array
@return array<model-property<User>, mixed>
resolved @return array<model-property<Nvl\Auth\Models\User>, mixed>
public function disabled(): static
public function modelName(): string
@return class-string<User>
resolved @return class-string<Nvl\Auth\Models\User>
public function unverified(): static
```

## Nvl\Auth\Enums\AuthFeature

```text
enum Nvl\Auth\Enums\AuthFeature implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\AuthFeature ApiTokens=Nvl\Auth\Enums\AuthFeature::ApiTokens="api_tokens"
public const Nvl\Auth\Enums\AuthFeature Audit=Nvl\Auth\Enums\AuthFeature::Audit="audit"
public const Nvl\Auth\Enums\AuthFeature Authentication=Nvl\Auth\Enums\AuthFeature::Authentication="authentication"
public const Nvl\Auth\Enums\AuthFeature Clients=Nvl\Auth\Enums\AuthFeature::Clients="clients"
public const Nvl\Auth\Enums\AuthFeature EmailVerification=Nvl\Auth\Enums\AuthFeature::EmailVerification="email_verification"
public const Nvl\Auth\Enums\AuthFeature Impersonation=Nvl\Auth\Enums\AuthFeature::Impersonation="impersonation"
public const Nvl\Auth\Enums\AuthFeature Invitations=Nvl\Auth\Enums\AuthFeature::Invitations="invitations"
public const Nvl\Auth\Enums\AuthFeature MagicLinks=Nvl\Auth\Enums\AuthFeature::MagicLinks="magic_links"
public const Nvl\Auth\Enums\AuthFeature ManagedSessions=Nvl\Auth\Enums\AuthFeature::ManagedSessions="managed_sessions"
public const Nvl\Auth\Enums\AuthFeature Memberships=Nvl\Auth\Enums\AuthFeature::Memberships="memberships"
public const Nvl\Auth\Enums\AuthFeature Passkeys=Nvl\Auth\Enums\AuthFeature::Passkeys="passkeys"
public const Nvl\Auth\Enums\AuthFeature Password=Nvl\Auth\Enums\AuthFeature::Password="password"
public const Nvl\Auth\Enums\AuthFeature PrincipalManagement=Nvl\Auth\Enums\AuthFeature::PrincipalManagement="principal_management"
public const Nvl\Auth\Enums\AuthFeature Rbac=Nvl\Auth\Enums\AuthFeature::Rbac="rbac"
public const Nvl\Auth\Enums\AuthFeature RecoveryCodes=Nvl\Auth\Enums\AuthFeature::RecoveryCodes="recovery_codes"
public const Nvl\Auth\Enums\AuthFeature Registration=Nvl\Auth\Enums\AuthFeature::Registration="registration"
public const Nvl\Auth\Enums\AuthFeature SecurityCodes=Nvl\Auth\Enums\AuthFeature::SecurityCodes="security_codes"
public const Nvl\Auth\Enums\AuthFeature Sessions=Nvl\Auth\Enums\AuthFeature::Sessions="sessions"
public const Nvl\Auth\Enums\AuthFeature SocialIdentities=Nvl\Auth\Enums\AuthFeature::SocialIdentities="social_identities"
public const Nvl\Auth\Enums\AuthFeature Totp=Nvl\Auth\Enums\AuthFeature::Totp="totp"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\AuthMessageType

```text
enum Nvl\Auth\Enums\AuthMessageType implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\AuthMessageType EmailChangeNotification=Nvl\Auth\Enums\AuthMessageType::EmailChangeNotification="email_change_notification"
public const Nvl\Auth\Enums\AuthMessageType EmailChangeVerification=Nvl\Auth\Enums\AuthMessageType::EmailChangeVerification="email_change_verification"
public const Nvl\Auth\Enums\AuthMessageType EmailVerification=Nvl\Auth\Enums\AuthMessageType::EmailVerification="email_verification"
public const Nvl\Auth\Enums\AuthMessageType Invitation=Nvl\Auth\Enums\AuthMessageType::Invitation="invitation"
public const Nvl\Auth\Enums\AuthMessageType MagicLink=Nvl\Auth\Enums\AuthMessageType::MagicLink="magic_link"
public const Nvl\Auth\Enums\AuthMessageType PasswordReset=Nvl\Auth\Enums\AuthMessageType::PasswordReset="password_reset"
public const Nvl\Auth\Enums\AuthMessageType RegistrationEmailVerification=Nvl\Auth\Enums\AuthMessageType::RegistrationEmailVerification="registration_email_verification"
public const Nvl\Auth\Enums\AuthMessageType SecurityCode=Nvl\Auth\Enums\AuthMessageType::SecurityCode="security_code"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\AuthResponseCode

```text
enum Nvl\Auth\Enums\AuthResponseCode implements BackedEnum, Nvl\Support\Contracts\ResponseCode, UnitEnum: string
public const Nvl\Auth\Enums\AuthResponseCode AccountConfirmationInvalid=Nvl\Auth\Enums\AuthResponseCode::AccountConfirmationInvalid="account_confirmation_invalid"
public const Nvl\Auth\Enums\AuthResponseCode AccountConfirmationRequired=Nvl\Auth\Enums\AuthResponseCode::AccountConfirmationRequired="account_confirmation_required"
public const Nvl\Auth\Enums\AuthResponseCode AccountDeleted=Nvl\Auth\Enums\AuthResponseCode::AccountDeleted="account_deleted"
public const Nvl\Auth\Enums\AuthResponseCode AmbiguousPermissionIdentifier=Nvl\Auth\Enums\AuthResponseCode::AmbiguousPermissionIdentifier="ambiguous_permission_identifier"
public const Nvl\Auth\Enums\AuthResponseCode AmbiguousRoleIdentifier=Nvl\Auth\Enums\AuthResponseCode::AmbiguousRoleIdentifier="ambiguous_role_identifier"
public const Nvl\Auth\Enums\AuthResponseCode ApiTokenAbilityForbidden=Nvl\Auth\Enums\AuthResponseCode::ApiTokenAbilityForbidden="api_token_ability_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode AuthAuditShown=Nvl\Auth\Enums\AuthResponseCode::AuthAuditShown="auth_audit_shown"
public const Nvl\Auth\Enums\AuthResponseCode AuthAuditsListed=Nvl\Auth\Enums\AuthResponseCode::AuthAuditsListed="auth_audits_listed"
public const Nvl\Auth\Enums\AuthResponseCode Authenticated=Nvl\Auth\Enums\AuthResponseCode::Authenticated="authenticated"
public const Nvl\Auth\Enums\AuthResponseCode AuthenticationRequired=Nvl\Auth\Enums\AuthResponseCode::AuthenticationRequired="authentication_required"
public const Nvl\Auth\Enums\AuthResponseCode ChallengeInvalid=Nvl\Auth\Enums\AuthResponseCode::ChallengeInvalid="challenge_invalid"
public const Nvl\Auth\Enums\AuthResponseCode ChallengeIssueConflict=Nvl\Auth\Enums\AuthResponseCode::ChallengeIssueConflict="challenge_issue_conflict"
public const Nvl\Auth\Enums\AuthResponseCode ClientActivated=Nvl\Auth\Enums\AuthResponseCode::ClientActivated="client_activated"
public const Nvl\Auth\Enums\AuthResponseCode ClientCreated=Nvl\Auth\Enums\AuthResponseCode::ClientCreated="client_created"
public const Nvl\Auth\Enums\AuthResponseCode ClientDeactivated=Nvl\Auth\Enums\AuthResponseCode::ClientDeactivated="client_deactivated"
public const Nvl\Auth\Enums\AuthResponseCode ClientDeleted=Nvl\Auth\Enums\AuthResponseCode::ClientDeleted="client_deleted"
public const Nvl\Auth\Enums\AuthResponseCode ClientOriginInvalid=Nvl\Auth\Enums\AuthResponseCode::ClientOriginInvalid="client_origin_invalid"
public const Nvl\Auth\Enums\AuthResponseCode ClientRedirectInvalid=Nvl\Auth\Enums\AuthResponseCode::ClientRedirectInvalid="client_redirect_invalid"
public const Nvl\Auth\Enums\AuthResponseCode ClientSessionConflict=Nvl\Auth\Enums\AuthResponseCode::ClientSessionConflict="client_session_conflict"
public const Nvl\Auth\Enums\AuthResponseCode ClientSessionEnded=Nvl\Auth\Enums\AuthResponseCode::ClientSessionEnded="client_session_ended"
public const Nvl\Auth\Enums\AuthResponseCode ClientSessionInputInvalid=Nvl\Auth\Enums\AuthResponseCode::ClientSessionInputInvalid="client_session_input_invalid"
public const Nvl\Auth\Enums\AuthResponseCode ClientSessionReasonInvalid=Nvl\Auth\Enums\AuthResponseCode::ClientSessionReasonInvalid="client_session_reason_invalid"
public const Nvl\Auth\Enums\AuthResponseCode ClientSessionUnavailable=Nvl\Auth\Enums\AuthResponseCode::ClientSessionUnavailable="client_session_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode ClientShown=Nvl\Auth\Enums\AuthResponseCode::ClientShown="client_shown"
public const Nvl\Auth\Enums\AuthResponseCode ClientStarted=Nvl\Auth\Enums\AuthResponseCode::ClientStarted="client_started"
public const Nvl\Auth\Enums\AuthResponseCode ClientUnavailable=Nvl\Auth\Enums\AuthResponseCode::ClientUnavailable="client_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode ClientUpdated=Nvl\Auth\Enums\AuthResponseCode::ClientUpdated="client_updated"
public const Nvl\Auth\Enums\AuthResponseCode ClientsListed=Nvl\Auth\Enums\AuthResponseCode::ClientsListed="clients_listed"
public const Nvl\Auth\Enums\AuthResponseCode CredentialsInvalid=Nvl\Auth\Enums\AuthResponseCode::CredentialsInvalid="credentials_invalid"
public const Nvl\Auth\Enums\AuthResponseCode DuplicatePermissionIdentifier=Nvl\Auth\Enums\AuthResponseCode::DuplicatePermissionIdentifier="duplicate_permission_identifier"
public const Nvl\Auth\Enums\AuthResponseCode DuplicateRoleIdentifier=Nvl\Auth\Enums\AuthResponseCode::DuplicateRoleIdentifier="duplicate_role_identifier"
public const Nvl\Auth\Enums\AuthResponseCode EmailUnavailable=Nvl\Auth\Enums\AuthResponseCode::EmailUnavailable="email_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode EmailVerificationRequested=Nvl\Auth\Enums\AuthResponseCode::EmailVerificationRequested="email_verification_requested"
public const Nvl\Auth\Enums\AuthResponseCode EmailVerified=Nvl\Auth\Enums\AuthResponseCode::EmailVerified="email_verified"
public const Nvl\Auth\Enums\AuthResponseCode FeatureUnavailable=Nvl\Auth\Enums\AuthResponseCode::FeatureUnavailable="feature_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode Forbidden=Nvl\Auth\Enums\AuthResponseCode::Forbidden="forbidden"
public const Nvl\Auth\Enums\AuthResponseCode InvalidAuditMetadata=Nvl\Auth\Enums\AuthResponseCode::InvalidAuditMetadata="invalid_audit_metadata"
public const Nvl\Auth\Enums\AuthResponseCode InvalidBulkSelection=Nvl\Auth\Enums\AuthResponseCode::InvalidBulkSelection="invalid_bulk_selection"
public const Nvl\Auth\Enums\AuthResponseCode InvalidConfiguration=Nvl\Auth\Enums\AuthResponseCode::InvalidConfiguration="invalid_configuration"
public const Nvl\Auth\Enums\AuthResponseCode InvalidMembershipFilter=Nvl\Auth\Enums\AuthResponseCode::InvalidMembershipFilter="invalid_membership_filter"
public const Nvl\Auth\Enums\AuthResponseCode InvalidPermissionCatalogQuery=Nvl\Auth\Enums\AuthResponseCode::InvalidPermissionCatalogQuery="invalid_permission_catalog_query"
public const Nvl\Auth\Enums\AuthResponseCode InvalidPermissionGroup=Nvl\Auth\Enums\AuthResponseCode::InvalidPermissionGroup="invalid_permission_group"
public const Nvl\Auth\Enums\AuthResponseCode InvalidPermissionIdentifier=Nvl\Auth\Enums\AuthResponseCode::InvalidPermissionIdentifier="invalid_permission_identifier"
public const Nvl\Auth\Enums\AuthResponseCode InvalidPermissionSearch=Nvl\Auth\Enums\AuthResponseCode::InvalidPermissionSearch="invalid_permission_search"
public const Nvl\Auth\Enums\AuthResponseCode InvalidRoleCatalogQuery=Nvl\Auth\Enums\AuthResponseCode::InvalidRoleCatalogQuery="invalid_role_catalog_query"
public const Nvl\Auth\Enums\AuthResponseCode InvalidRoleIdentifier=Nvl\Auth\Enums\AuthResponseCode::InvalidRoleIdentifier="invalid_role_identifier"
public const Nvl\Auth\Enums\AuthResponseCode InvalidRoleName=Nvl\Auth\Enums\AuthResponseCode::InvalidRoleName="invalid_role_name"
public const Nvl\Auth\Enums\AuthResponseCode InvalidRoleParent=Nvl\Auth\Enums\AuthResponseCode::InvalidRoleParent="invalid_role_parent"
public const Nvl\Auth\Enums\AuthResponseCode InvalidRoleSearch=Nvl\Auth\Enums\AuthResponseCode::InvalidRoleSearch="invalid_role_search"
public const Nvl\Auth\Enums\AuthResponseCode InvalidUserFilter=Nvl\Auth\Enums\AuthResponseCode::InvalidUserFilter="invalid_user_filter"
public const Nvl\Auth\Enums\AuthResponseCode InvalidUserSearch=Nvl\Auth\Enums\AuthResponseCode::InvalidUserSearch="invalid_user_search"
public const Nvl\Auth\Enums\AuthResponseCode InvitationAccepted=Nvl\Auth\Enums\AuthResponseCode::InvitationAccepted="invitation_accepted"
public const Nvl\Auth\Enums\AuthResponseCode InvitationAssignmentInvalid=Nvl\Auth\Enums\AuthResponseCode::InvitationAssignmentInvalid="invitation_assignment_invalid"
public const Nvl\Auth\Enums\AuthResponseCode InvitationDeliveryMetadataInvalid=Nvl\Auth\Enums\AuthResponseCode::InvitationDeliveryMetadataInvalid="invitation_delivery_metadata_invalid"
public const Nvl\Auth\Enums\AuthResponseCode InvitationExists=Nvl\Auth\Enums\AuthResponseCode::InvitationExists="invitation_exists"
public const Nvl\Auth\Enums\AuthResponseCode InvitationIdentityProofRequired=Nvl\Auth\Enums\AuthResponseCode::InvitationIdentityProofRequired="invitation_identity_proof_required"
public const Nvl\Auth\Enums\AuthResponseCode InvitationInvalid=Nvl\Auth\Enums\AuthResponseCode::InvitationInvalid="invitation_invalid"
public const Nvl\Auth\Enums\AuthResponseCode InvitationIssued=Nvl\Auth\Enums\AuthResponseCode::InvitationIssued="invitation_issued"
public const Nvl\Auth\Enums\AuthResponseCode InvitationPrincipalConflict=Nvl\Auth\Enums\AuthResponseCode::InvitationPrincipalConflict="invitation_principal_conflict"
public const Nvl\Auth\Enums\AuthResponseCode InvitationRegistrationInvalid=Nvl\Auth\Enums\AuthResponseCode::InvitationRegistrationInvalid="invitation_registration_invalid"
public const Nvl\Auth\Enums\AuthResponseCode InvitationResendLimited=Nvl\Auth\Enums\AuthResponseCode::InvitationResendLimited="invitation_resend_limited"
public const Nvl\Auth\Enums\AuthResponseCode InvitationResent=Nvl\Auth\Enums\AuthResponseCode::InvitationResent="invitation_resent"
public const Nvl\Auth\Enums\AuthResponseCode InvitationRevoked=Nvl\Auth\Enums\AuthResponseCode::InvitationRevoked="invitation_revoked"
public const Nvl\Auth\Enums\AuthResponseCode InvitationUnavailable=Nvl\Auth\Enums\AuthResponseCode::InvitationUnavailable="invitation_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode InvitationsListed=Nvl\Auth\Enums\AuthResponseCode::InvitationsListed="invitations_listed"
public const Nvl\Auth\Enums\AuthResponseCode LoggedOut=Nvl\Auth\Enums\AuthResponseCode::LoggedOut="logged_out"
public const Nvl\Auth\Enums\AuthResponseCode MagicLinkConsumed=Nvl\Auth\Enums\AuthResponseCode::MagicLinkConsumed="magic_link_consumed"
public const Nvl\Auth\Enums\AuthResponseCode MagicLinkRequested=Nvl\Auth\Enums\AuthResponseCode::MagicLinkRequested="magic_link_requested"
public const Nvl\Auth\Enums\AuthResponseCode MembershipAssignmentInvalid=Nvl\Auth\Enums\AuthResponseCode::MembershipAssignmentInvalid="membership_assignment_invalid"
public const Nvl\Auth\Enums\AuthResponseCode MembershipEnrolled=Nvl\Auth\Enums\AuthResponseCode::MembershipEnrolled="membership_enrolled"
public const Nvl\Auth\Enums\AuthResponseCode MembershipLastOwner=Nvl\Auth\Enums\AuthResponseCode::MembershipLastOwner="membership_last_owner"
public const Nvl\Auth\Enums\AuthResponseCode MembershipOwnershipInvalid=Nvl\Auth\Enums\AuthResponseCode::MembershipOwnershipInvalid="membership_ownership_invalid"
public const Nvl\Auth\Enums\AuthResponseCode MembershipOwnershipTransferred=Nvl\Auth\Enums\AuthResponseCode::MembershipOwnershipTransferred="membership_ownership_transferred"
public const Nvl\Auth\Enums\AuthResponseCode MembershipPrincipalIneligible=Nvl\Auth\Enums\AuthResponseCode::MembershipPrincipalIneligible="membership_principal_ineligible"
public const Nvl\Auth\Enums\AuthResponseCode MembershipPrincipalUnavailable=Nvl\Auth\Enums\AuthResponseCode::MembershipPrincipalUnavailable="membership_principal_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode MembershipRevisionConflict=Nvl\Auth\Enums\AuthResponseCode::MembershipRevisionConflict="membership_revision_conflict"
public const Nvl\Auth\Enums\AuthResponseCode MembershipRevoked=Nvl\Auth\Enums\AuthResponseCode::MembershipRevoked="membership_revoked"
public const Nvl\Auth\Enums\AuthResponseCode MembershipShown=Nvl\Auth\Enums\AuthResponseCode::MembershipShown="membership_shown"
public const Nvl\Auth\Enums\AuthResponseCode MembershipStatusUpdated=Nvl\Auth\Enums\AuthResponseCode::MembershipStatusUpdated="membership_status_updated"
public const Nvl\Auth\Enums\AuthResponseCode MembershipUnavailable=Nvl\Auth\Enums\AuthResponseCode::MembershipUnavailable="membership_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode MembershipsListed=Nvl\Auth\Enums\AuthResponseCode::MembershipsListed="memberships_listed"
public const Nvl\Auth\Enums\AuthResponseCode OperationFailed=Nvl\Auth\Enums\AuthResponseCode::OperationFailed="operation_failed"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyAuthenticated=Nvl\Auth\Enums\AuthResponseCode::PasskeyAuthenticated="passkey_authenticated"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyAuthenticationStarted=Nvl\Auth\Enums\AuthResponseCode::PasskeyAuthenticationStarted="passkey_authentication_started"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyBackupStateInvalid=Nvl\Auth\Enums\AuthResponseCode::PasskeyBackupStateInvalid="passkey_backup_state_invalid"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyCeremonyInvalid=Nvl\Auth\Enums\AuthResponseCode::PasskeyCeremonyInvalid="passkey_ceremony_invalid"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyCounterRegression=Nvl\Auth\Enums\AuthResponseCode::PasskeyCounterRegression="passkey_counter_regression"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyExists=Nvl\Auth\Enums\AuthResponseCode::PasskeyExists="passkey_exists"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyInputInvalid=Nvl\Auth\Enums\AuthResponseCode::PasskeyInputInvalid="passkey_input_invalid"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyInvalid=Nvl\Auth\Enums\AuthResponseCode::PasskeyInvalid="passkey_invalid"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyLimitReached=Nvl\Auth\Enums\AuthResponseCode::PasskeyLimitReached="passkey_limit_reached"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyProviderUnavailable=Nvl\Auth\Enums\AuthResponseCode::PasskeyProviderUnavailable="passkey_provider_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyRegistered=Nvl\Auth\Enums\AuthResponseCode::PasskeyRegistered="passkey_registered"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyRegistrationStarted=Nvl\Auth\Enums\AuthResponseCode::PasskeyRegistrationStarted="passkey_registration_started"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyRevoked=Nvl\Auth\Enums\AuthResponseCode::PasskeyRevoked="passkey_revoked"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyUnavailable=Nvl\Auth\Enums\AuthResponseCode::PasskeyUnavailable="passkey_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode PasskeyUserVerificationRequired=Nvl\Auth\Enums\AuthResponseCode::PasskeyUserVerificationRequired="passkey_user_verification_required"
public const Nvl\Auth\Enums\AuthResponseCode PasswordConfirmed=Nvl\Auth\Enums\AuthResponseCode::PasswordConfirmed="password_confirmed"
public const Nvl\Auth\Enums\AuthResponseCode PasswordInvalid=Nvl\Auth\Enums\AuthResponseCode::PasswordInvalid="password_invalid"
public const Nvl\Auth\Enums\AuthResponseCode PasswordResetInvalid=Nvl\Auth\Enums\AuthResponseCode::PasswordResetInvalid="password_reset_invalid"
public const Nvl\Auth\Enums\AuthResponseCode PasswordUpdated=Nvl\Auth\Enums\AuthResponseCode::PasswordUpdated="password_updated"
public const Nvl\Auth\Enums\AuthResponseCode PermissionCreated=Nvl\Auth\Enums\AuthResponseCode::PermissionCreated="permission_created"
public const Nvl\Auth\Enums\AuthResponseCode PermissionDeleted=Nvl\Auth\Enums\AuthResponseCode::PermissionDeleted="permission_deleted"
public const Nvl\Auth\Enums\AuthResponseCode PermissionIdentifierNotFound=Nvl\Auth\Enums\AuthResponseCode::PermissionIdentifierNotFound="permission_identifier_not_found"
public const Nvl\Auth\Enums\AuthResponseCode PermissionShown=Nvl\Auth\Enums\AuthResponseCode::PermissionShown="permission_shown"
public const Nvl\Auth\Enums\AuthResponseCode PermissionUpdated=Nvl\Auth\Enums\AuthResponseCode::PermissionUpdated="permission_updated"
public const Nvl\Auth\Enums\AuthResponseCode PermissionsListed=Nvl\Auth\Enums\AuthResponseCode::PermissionsListed="permissions_listed"
public const Nvl\Auth\Enums\AuthResponseCode PrincipalUnavailable=Nvl\Auth\Enums\AuthResponseCode::PrincipalUnavailable="principal_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode ProfileShown=Nvl\Auth\Enums\AuthResponseCode::ProfileShown="profile_shown"
public const Nvl\Auth\Enums\AuthResponseCode ProfileUpdated=Nvl\Auth\Enums\AuthResponseCode::ProfileUpdated="profile_updated"
public const Nvl\Auth\Enums\AuthResponseCode RbacAnalyticsShown=Nvl\Auth\Enums\AuthResponseCode::RbacAnalyticsShown="rbac_analytics_shown"
public const Nvl\Auth\Enums\AuthResponseCode RbacMixedContextOperation=Nvl\Auth\Enums\AuthResponseCode::RbacMixedContextOperation="rbac_mixed_context_operation"
public const Nvl\Auth\Enums\AuthResponseCode RbacSynchronized=Nvl\Auth\Enums\AuthResponseCode::RbacSynchronized="rbac_synchronized"
public const Nvl\Auth\Enums\AuthResponseCode RecoveryCodeConsumed=Nvl\Auth\Enums\AuthResponseCode::RecoveryCodeConsumed="recovery_code_consumed"
public const Nvl\Auth\Enums\AuthResponseCode RecoveryCodeInvalid=Nvl\Auth\Enums\AuthResponseCode::RecoveryCodeInvalid="recovery_code_invalid"
public const Nvl\Auth\Enums\AuthResponseCode RecoveryCodesRegenerated=Nvl\Auth\Enums\AuthResponseCode::RecoveryCodesRegenerated="recovery_codes_regenerated"
public const Nvl\Auth\Enums\AuthResponseCode RecoveryCodesRevoked=Nvl\Auth\Enums\AuthResponseCode::RecoveryCodesRevoked="recovery_codes_revoked"
public const Nvl\Auth\Enums\AuthResponseCode RoleCloned=Nvl\Auth\Enums\AuthResponseCode::RoleCloned="role_cloned"
public const Nvl\Auth\Enums\AuthResponseCode RoleCreated=Nvl\Auth\Enums\AuthResponseCode::RoleCreated="role_created"
public const Nvl\Auth\Enums\AuthResponseCode RoleDeleted=Nvl\Auth\Enums\AuthResponseCode::RoleDeleted="role_deleted"
public const Nvl\Auth\Enums\AuthResponseCode RoleHierarchyCycle=Nvl\Auth\Enums\AuthResponseCode::RoleHierarchyCycle="role_hierarchy_cycle"
public const Nvl\Auth\Enums\AuthResponseCode RoleHierarchyShown=Nvl\Auth\Enums\AuthResponseCode::RoleHierarchyShown="role_hierarchy_shown"
public const Nvl\Auth\Enums\AuthResponseCode RoleIdentifierNotFound=Nvl\Auth\Enums\AuthResponseCode::RoleIdentifierNotFound="role_identifier_not_found"
public const Nvl\Auth\Enums\AuthResponseCode RoleShown=Nvl\Auth\Enums\AuthResponseCode::RoleShown="role_shown"
public const Nvl\Auth\Enums\AuthResponseCode RoleTemplateApplied=Nvl\Auth\Enums\AuthResponseCode::RoleTemplateApplied="role_template_applied"
public const Nvl\Auth\Enums\AuthResponseCode RoleTemplateNotFound=Nvl\Auth\Enums\AuthResponseCode::RoleTemplateNotFound="role_template_not_found"
public const Nvl\Auth\Enums\AuthResponseCode RoleTemplatesListed=Nvl\Auth\Enums\AuthResponseCode::RoleTemplatesListed="role_templates_listed"
public const Nvl\Auth\Enums\AuthResponseCode RoleUpdated=Nvl\Auth\Enums\AuthResponseCode::RoleUpdated="role_updated"
public const Nvl\Auth\Enums\AuthResponseCode RolesListed=Nvl\Auth\Enums\AuthResponseCode::RolesListed="roles_listed"
public const Nvl\Auth\Enums\AuthResponseCode SecurityCodeAuthenticated=Nvl\Auth\Enums\AuthResponseCode::SecurityCodeAuthenticated="security_code_authenticated"
public const Nvl\Auth\Enums\AuthResponseCode SecurityCodeAuthenticationPurposeInvalid=Nvl\Auth\Enums\AuthResponseCode::SecurityCodeAuthenticationPurposeInvalid="security_code_authentication_purpose_invalid"
public const Nvl\Auth\Enums\AuthResponseCode SecurityCodeAuthenticationRequested=Nvl\Auth\Enums\AuthResponseCode::SecurityCodeAuthenticationRequested="security_code_authentication_requested"
public const Nvl\Auth\Enums\AuthResponseCode SecurityCodeRequested=Nvl\Auth\Enums\AuthResponseCode::SecurityCodeRequested="security_code_requested"
public const Nvl\Auth\Enums\AuthResponseCode SecurityCodeVerified=Nvl\Auth\Enums\AuthResponseCode::SecurityCodeVerified="security_code_verified"
public const Nvl\Auth\Enums\AuthResponseCode SelfBulkOperationForbidden=Nvl\Auth\Enums\AuthResponseCode::SelfBulkOperationForbidden="self_bulk_operation_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode SelfDeleteForbidden=Nvl\Auth\Enums\AuthResponseCode::SelfDeleteForbidden="self_delete_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode SelfDisableForbidden=Nvl\Auth\Enums\AuthResponseCode::SelfDisableForbidden="self_disable_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode SessionUnavailable=Nvl\Auth\Enums\AuthResponseCode::SessionUnavailable="session_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode SocialAuthenticated=Nvl\Auth\Enums\AuthResponseCode::SocialAuthenticated="social_authenticated"
public const Nvl\Auth\Enums\AuthResponseCode SocialAuthorizationFailed=Nvl\Auth\Enums\AuthResponseCode::SocialAuthorizationFailed="social_authorization_failed"
public const Nvl\Auth\Enums\AuthResponseCode SocialAuthorizationStarted=Nvl\Auth\Enums\AuthResponseCode::SocialAuthorizationStarted="social_authorization_started"
public const Nvl\Auth\Enums\AuthResponseCode SocialEmailUnverified=Nvl\Auth\Enums\AuthResponseCode::SocialEmailUnverified="social_email_unverified"
public const Nvl\Auth\Enums\AuthResponseCode SocialIdentityConflict=Nvl\Auth\Enums\AuthResponseCode::SocialIdentityConflict="social_identity_conflict"
public const Nvl\Auth\Enums\AuthResponseCode SocialIdentityLinked=Nvl\Auth\Enums\AuthResponseCode::SocialIdentityLinked="social_identity_linked"
public const Nvl\Auth\Enums\AuthResponseCode SocialIdentityRevoked=Nvl\Auth\Enums\AuthResponseCode::SocialIdentityRevoked="social_identity_revoked"
public const Nvl\Auth\Enums\AuthResponseCode SocialIdentityUnavailable=Nvl\Auth\Enums\AuthResponseCode::SocialIdentityUnavailable="social_identity_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode SocialLinkStarted=Nvl\Auth\Enums\AuthResponseCode::SocialLinkStarted="social_link_started"
public const Nvl\Auth\Enums\AuthResponseCode SocialProviderUnavailable=Nvl\Auth\Enums\AuthResponseCode::SocialProviderUnavailable="social_provider_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode SubjectIneligible=Nvl\Auth\Enums\AuthResponseCode::SubjectIneligible="subject_ineligible"
public const Nvl\Auth\Enums\AuthResponseCode SubjectUnavailable=Nvl\Auth\Enums\AuthResponseCode::SubjectUnavailable="subject_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode SystemMutationForbidden=Nvl\Auth\Enums\AuthResponseCode::SystemMutationForbidden="system_mutation_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode SystemPermissionDeleteForbidden=Nvl\Auth\Enums\AuthResponseCode::SystemPermissionDeleteForbidden="system_permission_delete_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode SystemPermissionImmutable=Nvl\Auth\Enums\AuthResponseCode::SystemPermissionImmutable="system_permission_immutable"
public const Nvl\Auth\Enums\AuthResponseCode SystemRoleDeleteForbidden=Nvl\Auth\Enums\AuthResponseCode::SystemRoleDeleteForbidden="system_role_delete_forbidden"
public const Nvl\Auth\Enums\AuthResponseCode SystemRoleImmutable=Nvl\Auth\Enums\AuthResponseCode::SystemRoleImmutable="system_role_immutable"
public const Nvl\Auth\Enums\AuthResponseCode TooManyPermissionIdentifiers=Nvl\Auth\Enums\AuthResponseCode::TooManyPermissionIdentifiers="too_many_permission_identifiers"
public const Nvl\Auth\Enums\AuthResponseCode TooManyRoleIdentifiers=Nvl\Auth\Enums\AuthResponseCode::TooManyRoleIdentifiers="too_many_role_identifiers"
public const Nvl\Auth\Enums\AuthResponseCode TotpEnrolled=Nvl\Auth\Enums\AuthResponseCode::TotpEnrolled="totp_enrolled"
public const Nvl\Auth\Enums\AuthResponseCode TotpEnrollmentStarted=Nvl\Auth\Enums\AuthResponseCode::TotpEnrollmentStarted="totp_enrollment_started"
public const Nvl\Auth\Enums\AuthResponseCode TotpInvalid=Nvl\Auth\Enums\AuthResponseCode::TotpInvalid="totp_invalid"
public const Nvl\Auth\Enums\AuthResponseCode TotpRevoked=Nvl\Auth\Enums\AuthResponseCode::TotpRevoked="totp_revoked"
public const Nvl\Auth\Enums\AuthResponseCode TotpSecurityStateShown=Nvl\Auth\Enums\AuthResponseCode::TotpSecurityStateShown="totp_security_state_shown"
public const Nvl\Auth\Enums\AuthResponseCode TotpUnavailable=Nvl\Auth\Enums\AuthResponseCode::TotpUnavailable="totp_unavailable"
public const Nvl\Auth\Enums\AuthResponseCode TotpVerified=Nvl\Auth\Enums\AuthResponseCode::TotpVerified="totp_verified"
public const Nvl\Auth\Enums\AuthResponseCode Unauthenticated=Nvl\Auth\Enums\AuthResponseCode::Unauthenticated="unauthenticated"
public const Nvl\Auth\Enums\AuthResponseCode UserCreated=Nvl\Auth\Enums\AuthResponseCode::UserCreated="user_created"
public const Nvl\Auth\Enums\AuthResponseCode UserDeleted=Nvl\Auth\Enums\AuthResponseCode::UserDeleted="user_deleted"
public const Nvl\Auth\Enums\AuthResponseCode UserDisabled=Nvl\Auth\Enums\AuthResponseCode::UserDisabled="user_disabled"
public const Nvl\Auth\Enums\AuthResponseCode UserEnabled=Nvl\Auth\Enums\AuthResponseCode::UserEnabled="user_enabled"
public const Nvl\Auth\Enums\AuthResponseCode UserPermissionsSynchronized=Nvl\Auth\Enums\AuthResponseCode::UserPermissionsSynchronized="user_permissions_synchronized"
public const Nvl\Auth\Enums\AuthResponseCode UserRestored=Nvl\Auth\Enums\AuthResponseCode::UserRestored="user_restored"
public const Nvl\Auth\Enums\AuthResponseCode UserRolesSynchronized=Nvl\Auth\Enums\AuthResponseCode::UserRolesSynchronized="user_roles_synchronized"
public const Nvl\Auth\Enums\AuthResponseCode UserShown=Nvl\Auth\Enums\AuthResponseCode::UserShown="user_shown"
public const Nvl\Auth\Enums\AuthResponseCode UserSuggestionsListed=Nvl\Auth\Enums\AuthResponseCode::UserSuggestionsListed="user_suggestions_listed"
public const Nvl\Auth\Enums\AuthResponseCode UserUpdated=Nvl\Auth\Enums\AuthResponseCode::UserUpdated="user_updated"
public const Nvl\Auth\Enums\AuthResponseCode UsersBulkUpdated=Nvl\Auth\Enums\AuthResponseCode::UsersBulkUpdated="users_bulk_updated"
public const Nvl\Auth\Enums\AuthResponseCode UsersListed=Nvl\Auth\Enums\AuthResponseCode::UsersListed="users_listed"
public const Nvl\Auth\Enums\AuthResponseCode VerificationInvalid=Nvl\Auth\Enums\AuthResponseCode::VerificationInvalid="verification_invalid"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\AuthenticationDestination

```text
enum Nvl\Auth\Enums\AuthenticationDestination implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\AuthenticationDestination ApiToken=Nvl\Auth\Enums\AuthenticationDestination::ApiToken="api_token"
public const Nvl\Auth\Enums\AuthenticationDestination Reauthentication=Nvl\Auth\Enums\AuthenticationDestination::Reauthentication="reauthentication"
public const Nvl\Auth\Enums\AuthenticationDestination Session=Nvl\Auth\Enums\AuthenticationDestination::Session="session"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\AuthenticationMethod

```text
enum Nvl\Auth\Enums\AuthenticationMethod implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\AuthenticationMethod EmailCode=Nvl\Auth\Enums\AuthenticationMethod::EmailCode="email_code"
public const Nvl\Auth\Enums\AuthenticationMethod EmailLink=Nvl\Auth\Enums\AuthenticationMethod::EmailLink="email_link"
public const Nvl\Auth\Enums\AuthenticationMethod Passkey=Nvl\Auth\Enums\AuthenticationMethod::Passkey="passkey"
public const Nvl\Auth\Enums\AuthenticationMethod Password=Nvl\Auth\Enums\AuthenticationMethod::Password="password"
public const Nvl\Auth\Enums\AuthenticationMethod Remember=Nvl\Auth\Enums\AuthenticationMethod::Remember="remember"
public const Nvl\Auth\Enums\AuthenticationMethod Social=Nvl\Auth\Enums\AuthenticationMethod::Social="social"
public function purpose(): Nvl\Auth\Enums\AuthenticationPurpose
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\AuthenticationPurpose

```text
enum Nvl\Auth\Enums\AuthenticationPurpose implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\AuthenticationPurpose CredentialLogin=Nvl\Auth\Enums\AuthenticationPurpose::CredentialLogin="credential_login"
public const Nvl\Auth\Enums\AuthenticationPurpose PasswordReset=Nvl\Auth\Enums\AuthenticationPurpose::PasswordReset="password_reset"
public const Nvl\Auth\Enums\AuthenticationPurpose PasswordlessLogin=Nvl\Auth\Enums\AuthenticationPurpose::PasswordlessLogin="passwordless_login"
public const Nvl\Auth\Enums\AuthenticationPurpose SocialLogin=Nvl\Auth\Enums\AuthenticationPurpose::SocialLogin="social_login"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\FeatureOperation

```text
enum Nvl\Auth\Enums\FeatureOperation implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\FeatureOperation Cleanup=Nvl\Auth\Enums\FeatureOperation::Cleanup="cleanup"
public const Nvl\Auth\Enums\FeatureOperation Enroll=Nvl\Auth\Enums\FeatureOperation::Enroll="enroll"
public const Nvl\Auth\Enums\FeatureOperation Issue=Nvl\Auth\Enums\FeatureOperation::Issue="issue"
public const Nvl\Auth\Enums\FeatureOperation Read=Nvl\Auth\Enums\FeatureOperation::Read="read"
public const Nvl\Auth\Enums\FeatureOperation Revoke=Nvl\Auth\Enums\FeatureOperation::Revoke="revoke"
public const Nvl\Auth\Enums\FeatureOperation Update=Nvl\Auth\Enums\FeatureOperation::Update="update"
public const Nvl\Auth\Enums\FeatureOperation Use=Nvl\Auth\Enums\FeatureOperation::Use="use"
public function isContainment(): bool
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\InvitationDeliveryStatus

```text
enum Nvl\Auth\Enums\InvitationDeliveryStatus implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\InvitationDeliveryStatus Delivered=Nvl\Auth\Enums\InvitationDeliveryStatus::Delivered="delivered"
public const Nvl\Auth\Enums\InvitationDeliveryStatus Failed=Nvl\Auth\Enums\InvitationDeliveryStatus::Failed="failed"
public const Nvl\Auth\Enums\InvitationDeliveryStatus Pending=Nvl\Auth\Enums\InvitationDeliveryStatus::Pending="pending"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\MembershipStatus

```text
enum Nvl\Auth\Enums\MembershipStatus implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\MembershipStatus Active=Nvl\Auth\Enums\MembershipStatus::Active="active"
public const Nvl\Auth\Enums\MembershipStatus Revoked=Nvl\Auth\Enums\MembershipStatus::Revoked="revoked"
public const Nvl\Auth\Enums\MembershipStatus Suspended=Nvl\Auth\Enums\MembershipStatus::Suspended="suspended"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\OwnerAuthenticationPurpose

```text
enum Nvl\Auth\Enums\OwnerAuthenticationPurpose implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose Invitation=Nvl\Auth\Enums\OwnerAuthenticationPurpose::Invitation="invitation"
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose Login=Nvl\Auth\Enums\OwnerAuthenticationPurpose::Login="login"
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose MagicLink=Nvl\Auth\Enums\OwnerAuthenticationPurpose::MagicLink="magic_link"
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose PasskeyLogin=Nvl\Auth\Enums\OwnerAuthenticationPurpose::PasskeyLogin="passkey_login"
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose SecurityCode=Nvl\Auth\Enums\OwnerAuthenticationPurpose::SecurityCode="security_code"
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose SocialLink=Nvl\Auth\Enums\OwnerAuthenticationPurpose::SocialLink="social_link"
public const Nvl\Auth\Enums\OwnerAuthenticationPurpose SocialLogin=Nvl\Auth\Enums\OwnerAuthenticationPurpose::SocialLogin="social_login"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\PrincipalAttribute

```text
enum Nvl\Auth\Enums\PrincipalAttribute implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\PrincipalAttribute Active=Nvl\Auth\Enums\PrincipalAttribute::Active="active"
public const Nvl\Auth\Enums\PrincipalAttribute CreatedAt=Nvl\Auth\Enums\PrincipalAttribute::CreatedAt="created_at"
public const Nvl\Auth\Enums\PrincipalAttribute DeletedAt=Nvl\Auth\Enums\PrincipalAttribute::DeletedAt="deleted_at"
public const Nvl\Auth\Enums\PrincipalAttribute Email=Nvl\Auth\Enums\PrincipalAttribute::Email="email"
public const Nvl\Auth\Enums\PrincipalAttribute EmailIdentityHash=Nvl\Auth\Enums\PrincipalAttribute::EmailIdentityHash="email_identity_hash"
public const Nvl\Auth\Enums\PrincipalAttribute EmailVerifiedAt=Nvl\Auth\Enums\PrincipalAttribute::EmailVerifiedAt="email_verified_at"
public const Nvl\Auth\Enums\PrincipalAttribute Id=Nvl\Auth\Enums\PrincipalAttribute::Id="id"
public const Nvl\Auth\Enums\PrincipalAttribute LastLoginAt=Nvl\Auth\Enums\PrincipalAttribute::LastLoginAt="last_login_at"
public const Nvl\Auth\Enums\PrincipalAttribute LastLoginIp=Nvl\Auth\Enums\PrincipalAttribute::LastLoginIp="last_login_ip"
public const Nvl\Auth\Enums\PrincipalAttribute Locale=Nvl\Auth\Enums\PrincipalAttribute::Locale="locale"
public const Nvl\Auth\Enums\PrincipalAttribute LockedUntil=Nvl\Auth\Enums\PrincipalAttribute::LockedUntil="locked_until"
public const Nvl\Auth\Enums\PrincipalAttribute Name=Nvl\Auth\Enums\PrincipalAttribute::Name="name"
public const Nvl\Auth\Enums\PrincipalAttribute Password=Nvl\Auth\Enums\PrincipalAttribute::Password="password"
public const Nvl\Auth\Enums\PrincipalAttribute Preferences=Nvl\Auth\Enums\PrincipalAttribute::Preferences="preferences"
public const Nvl\Auth\Enums\PrincipalAttribute Profile=Nvl\Auth\Enums\PrincipalAttribute::Profile="profile"
public const Nvl\Auth\Enums\PrincipalAttribute RememberToken=Nvl\Auth\Enums\PrincipalAttribute::RememberToken="remember_token"
public const Nvl\Auth\Enums\PrincipalAttribute Timezone=Nvl\Auth\Enums\PrincipalAttribute::Timezone="timezone"
public const Nvl\Auth\Enums\PrincipalAttribute UpdatedAt=Nvl\Auth\Enums\PrincipalAttribute::UpdatedAt="updated_at"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\PrincipalMutation

```text
enum Nvl\Auth\Enums\PrincipalMutation implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\PrincipalMutation InvitationRegistration=Nvl\Auth\Enums\PrincipalMutation::InvitationRegistration="invitation_registration"
public const Nvl\Auth\Enums\PrincipalMutation ManagementCreate=Nvl\Auth\Enums\PrincipalMutation::ManagementCreate="management_create"
public const Nvl\Auth\Enums\PrincipalMutation ManagementUpdate=Nvl\Auth\Enums\PrincipalMutation::ManagementUpdate="management_update"
public const Nvl\Auth\Enums\PrincipalMutation Profile=Nvl\Auth\Enums\PrincipalMutation::Profile="profile"
public const Nvl\Auth\Enums\PrincipalMutation Registration=Nvl\Auth\Enums\PrincipalMutation::Registration="registration"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\RecentAuthenticationPurpose

```text
enum Nvl\Auth\Enums\RecentAuthenticationPurpose implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\RecentAuthenticationPurpose AccountDeletion=Nvl\Auth\Enums\RecentAuthenticationPurpose::AccountDeletion="account_deletion"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose EmailChange=Nvl\Auth\Enums\RecentAuthenticationPurpose::EmailChange="email_change"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose FactorEnrollment=Nvl\Auth\Enums\RecentAuthenticationPurpose::FactorEnrollment="factor_enrollment"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose FactorRemoval=Nvl\Auth\Enums\RecentAuthenticationPurpose::FactorRemoval="factor_removal"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose ImpersonationStart=Nvl\Auth\Enums\RecentAuthenticationPurpose::ImpersonationStart="impersonation_start"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose PasswordChange=Nvl\Auth\Enums\RecentAuthenticationPurpose::PasswordChange="password_change"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose RecoveryRegeneration=Nvl\Auth\Enums\RecentAuthenticationPurpose::RecoveryRegeneration="recovery_regeneration"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose SessionRevocation=Nvl\Auth\Enums\RecentAuthenticationPurpose::SessionRevocation="session_revocation"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose SocialLink=Nvl\Auth\Enums\RecentAuthenticationPurpose::SocialLink="social_link"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose SocialReconnect=Nvl\Auth\Enums\RecentAuthenticationPurpose::SocialReconnect="social_reconnect"
public const Nvl\Auth\Enums\RecentAuthenticationPurpose SocialUnlink=Nvl\Auth\Enums\RecentAuthenticationPurpose::SocialUnlink="social_unlink"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\RegistrationMethod

```text
enum Nvl\Auth\Enums\RegistrationMethod implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\RegistrationMethod Password=Nvl\Auth\Enums\RegistrationMethod::Password="password"
public const Nvl\Auth\Enums\RegistrationMethod Social=Nvl\Auth\Enums\RegistrationMethod::Social="social"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\RegistrationMode

```text
enum Nvl\Auth\Enums\RegistrationMode implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\RegistrationMode Closed=Nvl\Auth\Enums\RegistrationMode::Closed="closed"
public const Nvl\Auth\Enums\RegistrationMode InvitationOnly=Nvl\Auth\Enums\RegistrationMode::InvitationOnly="invitation_only"
public const Nvl\Auth\Enums\RegistrationMode Open=Nvl\Auth\Enums\RegistrationMode::Open="open"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\SocialIntentPurpose

```text
enum Nvl\Auth\Enums\SocialIntentPurpose implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\SocialIntentPurpose Link=Nvl\Auth\Enums\SocialIntentPurpose::Link="link"
public const Nvl\Auth\Enums\SocialIntentPurpose Login=Nvl\Auth\Enums\SocialIntentPurpose::Login="login"
public const Nvl\Auth\Enums\SocialIntentPurpose Reauthentication=Nvl\Auth\Enums\SocialIntentPurpose::Reauthentication="reauthentication"
public const Nvl\Auth\Enums\SocialIntentPurpose Reconnect=Nvl\Auth\Enums\SocialIntentPurpose::Reconnect="reconnect"
public const Nvl\Auth\Enums\SocialIntentPurpose Registration=Nvl\Auth\Enums\SocialIntentPurpose::Registration="registration"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Enums\UserBulkOperation

```text
enum Nvl\Auth\Enums\UserBulkOperation implements BackedEnum, UnitEnum: string
public const Nvl\Auth\Enums\UserBulkOperation Delete=Nvl\Auth\Enums\UserBulkOperation::Delete="delete"
public const Nvl\Auth\Enums\UserBulkOperation Disable=Nvl\Auth\Enums\UserBulkOperation::Disable="disable"
public const Nvl\Auth\Enums\UserBulkOperation Enable=Nvl\Auth\Enums\UserBulkOperation::Enable="enable"
public const Nvl\Auth\Enums\UserBulkOperation Restore=Nvl\Auth\Enums\UserBulkOperation::Restore="restore"
public readonly string $name
public static function cases(): array
public readonly string $value
public static function from(string|int $value): static
public static function tryFrom(string|int $value): ?static
```

## Nvl\Auth\Events\AccountSecurityChanged

```text
final readonly class Nvl\Auth\Events\AccountSecurityChanged implements Nvl\Support\Contracts\DomainEvent
public function __construct(Nvl\Auth\ValueObjects\SubjectReference $subject, string $operation, ?string $credentialId=null, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly ?string $credentialId
public readonly string $operation
public readonly int $schemaVersion
public readonly Nvl\Auth\ValueObjects\SubjectReference $subject
```

## Nvl\Auth\Events\AuthAuditRecorded

```text
final class Nvl\Auth\Events\AuthAuditRecorded implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $auditId, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly string $auditId
public readonly int $schemaVersion
```

## Nvl\Auth\Events\AuthDeliveryRequested

```text
final readonly class Nvl\Auth\Events\AuthDeliveryRequested implements Nvl\Support\Contracts\DomainEvent, Nvl\Support\Ownership\Contracts\OwnershipQueuedJob
public function __construct(Nvl\Auth\ValueObjects\AuthDeliveryRequest $request, Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope $ownership, int $schemaVersion=1): mixed
public function ownershipJobEnvelope(): Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope
public function schemaVersion(): int
public readonly Nvl\Auth\ValueObjects\AuthDeliveryRequest $request
public readonly int $schemaVersion
```

## Nvl\Auth\Events\AuthenticationAttempted

```text
final class Nvl\Auth\Events\AuthenticationAttempted implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $identifierName, string $identifier, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly string $identifier
public readonly string $identifierName
public readonly int $schemaVersion
```

## Nvl\Auth\Events\AuthenticationRejected

```text
final class Nvl\Auth\Events\AuthenticationRejected implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $identifierName, string $identifier, string $reason, ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly string $identifier
public readonly string $identifierName
public readonly string $reason
public readonly int $schemaVersion
public readonly ?Nvl\Auth\ValueObjects\SubjectReference $subject
```

## Nvl\Auth\Events\ImpersonationChanged

```text
final readonly class Nvl\Auth\Events\ImpersonationChanged implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $impersonationId, Nvl\Auth\ValueObjects\SubjectReference $originalActor, Nvl\Auth\ValueObjects\SubjectReference $effectiveSubject, string $operation, Carbon\CarbonImmutable $expiresAt, ?Nvl\Auth\ValueObjects\SubjectReference $operator=null, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly Nvl\Auth\ValueObjects\SubjectReference $effectiveSubject
public readonly Carbon\CarbonImmutable $expiresAt
public readonly string $impersonationId
public readonly string $operation
public readonly ?Nvl\Auth\ValueObjects\SubjectReference $operator
public readonly Nvl\Auth\ValueObjects\SubjectReference $originalActor
public readonly int $schemaVersion
```

## Nvl\Auth\Events\InvitationAccepted

```text
final class Nvl\Auth\Events\InvitationAccepted implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $invitationId, string $type, string $purpose, Nvl\Auth\ValueObjects\SubjectReference $subject, ?Carbon\CarbonImmutable $acceptedAt=null, ?Nvl\Auth\ValueObjects\AuthEventContext $context=null, int $schemaVersion=1): mixed
public function __serialize(): array
@return array<string, mixed>
public function __unserialize(array $data): void
@param array{invitationId: string, type: string, purpose: string, subject: SubjectReference, acceptedAt?: (CarbonImmutable | null), context?: (AuthEventContext | null), schemaVersion?: int} $data
resolved @param array{invitationId: string, type: string, purpose: string, subject: Nvl\Auth\ValueObjects\SubjectReference, acceptedAt?: (Carbon\CarbonImmutable | null), context?: (Nvl\Auth\ValueObjects\AuthEventContext | null), schemaVersion?: int} $data
public function schemaVersion(): int
public readonly ?Carbon\CarbonImmutable $acceptedAt
public readonly ?Nvl\Auth\ValueObjects\AuthEventContext $context
public readonly string $invitationId
public readonly string $purpose
public readonly int $schemaVersion
public readonly Nvl\Auth\ValueObjects\SubjectReference $subject
public readonly string $type
```

## Nvl\Auth\Events\PrincipalChanged

```text
final class Nvl\Auth\Events\PrincipalChanged implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $userId, string $operation, array $payload=[], ?Nvl\Auth\ValueObjects\AuthEventContext $context=null, int $schemaVersion=1): mixed
@param array<string, mixed> $payload
public function schemaVersion(): int
public readonly ?Nvl\Auth\ValueObjects\AuthEventContext $context
public readonly string $operation
public readonly array $payload
@param array<string, mixed> $payload
public readonly int $schemaVersion
public readonly string $userId
```

## Nvl\Auth\Events\PrincipalRegistered

```text
final readonly class Nvl\Auth\Events\PrincipalRegistered implements Nvl\Support\Contracts\DomainEvent
public function __construct(Nvl\Auth\ValueObjects\SubjectReference $subject, Nvl\Auth\Enums\RegistrationMethod $method, string $classification="public", int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly string $classification
public readonly Nvl\Auth\Enums\RegistrationMethod $method
public readonly int $schemaVersion
public readonly Nvl\Auth\ValueObjects\SubjectReference $subject
```

## Nvl\Auth\Events\RbacAssignmentChanged

```text
final class Nvl\Auth\Events\RbacAssignmentChanged implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $principalId, string $operation, array $roles=[], array $permissions=[], array $metadata=[], ?Nvl\Auth\ValueObjects\AuthEventContext $context=null, int $schemaVersion=1): mixed
@param list<string> $roles
@param list<string> $permissions
@param array<string, mixed> $metadata
public function schemaVersion(): int
public readonly ?Nvl\Auth\ValueObjects\AuthEventContext $context
public readonly array $metadata
@param array<string, mixed> $metadata
public readonly string $operation
public readonly array $permissions
@param list<string> $permissions
public readonly string $principalId
public readonly array $roles
@param list<string> $roles
public readonly int $schemaVersion
```

## Nvl\Auth\Events\RbacChanged

```text
final class Nvl\Auth\Events\RbacChanged implements Nvl\Support\Contracts\DomainEvent
public function __construct(string $entityType, string $entityId, string $operation, array $payload=[], int $schemaVersion=1): mixed
@param array<string, mixed> $payload
public function schemaVersion(): int
public readonly string $entityId
public readonly string $entityType
public readonly string $operation
public readonly array $payload
@param array<string, mixed> $payload
public readonly int $schemaVersion
```

## Nvl\Auth\Events\UserAuthenticated

```text
final class Nvl\Auth\Events\UserAuthenticated implements Nvl\Support\Contracts\DomainEvent
public function __construct(Nvl\Auth\ValueObjects\SubjectReference $subject, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly int $schemaVersion
public readonly Nvl\Auth\ValueObjects\SubjectReference $subject
```

## Nvl\Auth\Events\UserLoggedOut

```text
final class Nvl\Auth\Events\UserLoggedOut implements Nvl\Support\Contracts\DomainEvent
public function __construct(?Nvl\Auth\ValueObjects\SubjectReference $subject, int $schemaVersion=1): mixed
public function schemaVersion(): int
public readonly int $schemaVersion
public readonly ?Nvl\Auth\ValueObjects\SubjectReference $subject
```

## Nvl\Auth\Exceptions\AuthException

```text
final class Nvl\Auth\Exceptions\AuthException extends RuntimeException implements Nvl\Support\Contracts\RespondableException
public function __construct(string $errorCode, string $message, int $status=422, array $context=[], ?Throwable $previous=null): mixed
@param array<string, mixed> $context
public static function because(Nvl\Auth\Enums\AuthResponseCode $code, string $diagnosticMessage, int $status=422, array $context=[], ?Throwable $previous=null): self
@param array<string, mixed> $context
public static function featureUnavailable(Nvl\Auth\Enums\AuthFeature|string $feature, Nvl\Auth\Enums\FeatureOperation|string $operation, array $dependencies=[]): self
@param list<string> $dependencies
public static function invalidConfiguration(string $message): self
public function package(): string
public function publicContext(): array
@return array<string, mixed>
public function responseCode(): string
public function responseHeaders(): array
@return array<string, string>
public function suggestedStatus(): int
public function translationKey(): ?string
public function translationParameters(): array
@return array<string, (scalar | null)>
public readonly array $context
@param array<string, mixed> $context
public readonly string $errorCode
public readonly int $status
```

## Nvl\Auth\Models\AuthAudit

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\AuthAuditFactory::class)]
final class Nvl\Auth\Models\AuthAudit extends Nvl\Auth\Models\AuthModel implements Nvl\Support\Ownership\Contracts\Ownable
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Audits
public function client(): Illuminate\Database\Eloquent\Relations\BelongsTo
@return BelongsTo<AuthClient, $this>
resolved @return Illuminate\Database\Eloquent\Relations\BelongsTo<Nvl\Auth\Models\AuthClient, $this>
public function delete(): mixed
@return ($this is Pivot ? (bool | int | null) : (bool | null))
resolved @return ($this is Illuminate\Database\Eloquent\Relations\Pivot ? (bool | int | null) : (bool | null))
public function fresh(mixed $with=[]): ?static
@param (array<array-key, mixed> | string) $with
public function getConnectionName(): ?string
public function identifier(): string
public function newQueryForRestoration(mixed $ids): Illuminate\Database\Eloquent\Builder
@param (int | string | array<array-key, (int | string)>) $ids
@return Builder<static>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\AuthAudit>
public static function ownershipDefinition(): Nvl\Support\Ownership\ValueObjects\OwnershipDefinition
public function refresh(): static
public function refreshForUpdate(): static
public function save(array $options=[]): bool
@param array<string, mixed> $options
@property string $action
@property (string | null) $actor_id
@property (string | null) $actor_type
@property (string | null) $client_id
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $id
@property (string | null) $ip_address
@property (array<string, mixed> | null) $metadata
@property string $outcome
@property (string | null) $owner_reference
@property (string | null) $owner_scope_key
@property (string | null) $request_id
@property (string | null) $subject_id
@property (string | null) $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
@property (string | null) $user_agent
```

## Nvl\Auth\Models\AuthClient

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\AuthClientFactory::class)]
final class Nvl\Auth\Models\AuthClient extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Clients
public function getConnectionName(): ?string
public function identifier(): string
public function sessions(): Illuminate\Database\Eloquent\Relations\HasMany
@return HasMany<AuthClientSession, $this>
resolved @return Illuminate\Database\Eloquent\Relations\HasMany<Nvl\Auth\Models\AuthClientSession, $this>
@property (list<string> | null) $allowed_flows
@property (list<string> | null) $allowed_origins
@property string $base_url
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $id
@property bool $is_active
@property (CarbonImmutable | null) $last_used_at
resolved @property (Carbon\CarbonImmutable | null) $last_used_at
@property (array<string, mixed> | null) $metadata
@property string $name
@property (list<string> | null) $return_paths
@property string $surface
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\AuthClientSession

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\AuthClientSessionFactory::class)]
final class Nvl\Auth\Models\AuthClientSession extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::ClientSessions
public function client(): Illuminate\Database\Eloquent\Relations\BelongsTo
@return BelongsTo<AuthClient, $this>
resolved @return Illuminate\Database\Eloquent\Relations\BelongsTo<Nvl\Auth\Models\AuthClient, $this>
public function getConnectionName(): ?string
public function identifier(): string
@property (CarbonImmutable | null) $authenticated_at
resolved @property (Carbon\CarbonImmutable | null) $authenticated_at
@property string $client_id
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property (string | null) $end_reason
@property (CarbonImmutable | null) $ended_at
resolved @property (Carbon\CarbonImmutable | null) $ended_at
@property string $id
@property (string | null) $ip_address
@property CarbonImmutable $last_seen_at
resolved @property Carbon\CarbonImmutable $last_seen_at
@property (array<string, mixed> | null) $metadata
@property string $session_id_hash
@property (string | null) $subject_id
@property (string | null) $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
@property (string | null) $user_agent
```

## Nvl\Auth\Models\BrowserSession

```text
final class Nvl\Auth\Models\BrowserSession extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::BrowserSessions
public function getConnectionName(): ?string
public function identifier(): string
public function isCurrent(int $revision): bool
@property CarbonImmutable $absolute_expires_at
resolved @property Carbon\CarbonImmutable $absolute_expires_at
@property array<string, mixed> $assurance
@property CarbonImmutable $authenticated_at
resolved @property Carbon\CarbonImmutable $authenticated_at
@property string $binding_hash
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $guard_name
@property string $id
@property (string | null) $ip_address
@property CarbonImmutable $last_seen_at
resolved @property Carbon\CarbonImmutable $last_seen_at
@property string $method
@property string $provider_hash
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property int $security_revision
@property string $session_family_id
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
@property (string | null) $user_agent
```

## Nvl\Auth\Models\Challenge

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\ChallengeFactory::class)]
final class Nvl\Auth\Models\Challenge extends Nvl\Auth\Models\AuthModel implements Nvl\Support\Ownership\Contracts\Ownable
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Challenges
public function delete(): mixed
@return ($this is Pivot ? (bool | int | null) : (bool | null))
resolved @return ($this is Illuminate\Database\Eloquent\Relations\Pivot ? (bool | int | null) : (bool | null))
public function fresh(mixed $with=[]): ?static
@param (array<array-key, mixed> | string) $with
public function getConnectionName(): ?string
public function identifier(): string
public function isUsable(): bool
public function newQueryForRestoration(mixed $ids): Illuminate\Database\Eloquent\Builder
@param (int | string | array<array-key, (int | string)>) $ids
@return Builder<static>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\Challenge>
public static function ownershipDefinition(): Nvl\Support\Ownership\ValueObjects\OwnershipDefinition
public function refresh(): static
public function refreshForUpdate(): static
public function save(array $options=[]): bool
@param array<string, mixed> $options
@property (string | null) $active_key
@property int $attempts
@property (CarbonImmutable | null) $consumed_at
resolved @property (Carbon\CarbonImmutable | null) $consumed_at
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property CarbonImmutable $expires_at
resolved @property Carbon\CarbonImmutable $expires_at
@property string $id
@property int $max_attempts
@property (string | null) $owner_reference
@property (string | null) $owner_scope_key
@property (array<string, mixed> | null) $payload
@property string $purpose
@property (string | null) $recipient_hash
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property (string | null) $secondary_secret_hash
@property string $secret_hash
@property (string | null) $subject_id
@property (string | null) $subject_type
@property string $type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\Impersonation

```text
final class Nvl\Auth\Models\Impersonation extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Impersonations
public function getConnectionName(): ?string
public function identifier(): string
@property (string | null) $active_session_key
@property string $actor_id
@property int $actor_revision
@property string $actor_type
@property string $browser_session_id
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $effective_subject_id
@property string $effective_subject_type
@property CarbonImmutable $expires_at
resolved @property Carbon\CarbonImmutable $expires_at
@property string $guard_name
@property string $id
@property (array<string, mixed> | null) $owner_reference
@property string $reason
@property CarbonImmutable $started_at
resolved @property Carbon\CarbonImmutable $started_at
@property (string | null) $stop_reason
@property (CarbonImmutable | null) $stopped_at
resolved @property (Carbon\CarbonImmutable | null) $stopped_at
@property int $target_revision
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\Invitation

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\InvitationFactory::class)]
final class Nvl\Auth\Models\Invitation extends Nvl\Auth\Models\AuthModel implements Nvl\Support\Ownership\Contracts\Ownable
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Invitations
public function delete(): mixed
@return ($this is Pivot ? (bool | int | null) : (bool | null))
resolved @return ($this is Illuminate\Database\Eloquent\Relations\Pivot ? (bool | int | null) : (bool | null))
public function fresh(mixed $with=[]): ?static
@param (array<array-key, mixed> | string) $with
public function getConnectionName(): ?string
public function identifier(): string
public function isUsable(): bool
public function newQueryForRestoration(mixed $ids): Illuminate\Database\Eloquent\Builder
@param (int | string | array<array-key, (int | string)>) $ids
@return Builder<static>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\Invitation>
public static function ownershipDefinition(): Nvl\Support\Ownership\ValueObjects\OwnershipDefinition
public function refresh(): static
public function refreshForUpdate(): static
public function save(array $options=[]): bool
@param array<string, mixed> $options
@property (CarbonImmutable | null) $accepted_at
resolved @property (Carbon\CarbonImmutable | null) $accepted_at
@property (string | null) $accepted_by_id
@property (string | null) $accepted_by_type
@property (string | null) $active_key
@property (string | null) $context_hash
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property (string | null) $current_delivery_message_id
@property (CarbonImmutable | null) $delivered_at
resolved @property (Carbon\CarbonImmutable | null) $delivered_at
@property (CarbonImmutable | null) $delivery_attempted_at
resolved @property (Carbon\CarbonImmutable | null) $delivery_attempted_at
@property (CarbonImmutable | null) $delivery_failed_at
resolved @property (Carbon\CarbonImmutable | null) $delivery_failed_at
@property (string | null) $delivery_failure_code
@property (InvitationDeliveryStatus | null) $delivery_status
resolved @property (Nvl\Auth\Enums\InvitationDeliveryStatus | null) $delivery_status
@property CarbonImmutable $expires_at
resolved @property Carbon\CarbonImmutable $expires_at
@property string $id
@property (string | null) $inviter_id
@property (string | null) $inviter_type
@property (CarbonImmutable | null) $last_sent_at
resolved @property (Carbon\CarbonImmutable | null) $last_sent_at
@property (array<string, mixed> | null) $metadata
@property (string | null) $owner_reference
@property (string | null) $owner_scope_key
@property (list<string> | null) $permissions
@property string $purpose
@property string $recipient
@property string $recipient_hash
@property int $resend_count
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property (list<string> | null) $roles
@property string $token_hash
@property string $type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\Membership

```text
abstract class Nvl\Auth\Models\Membership extends Nvl\Auth\Models\AuthModel
public function getConnectionName(): ?string
public function identifier(): string
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $id
@property bool $is_owner
@property int $revision
@property MembershipStatus $status
resolved @property Nvl\Auth\Enums\MembershipStatus $status
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\OwnerMembership

```text
class Nvl\Auth\Models\OwnerMembership extends Nvl\Auth\Models\Membership implements Nvl\Support\Ownership\Contracts\Ownable
public function delete(): mixed
@return ($this is Pivot ? (bool | int | null) : (bool | null))
resolved @return ($this is Illuminate\Database\Eloquent\Relations\Pivot ? (bool | int | null) : (bool | null))
public function fresh(mixed $with=[]): ?static
@param (array<array-key, mixed> | string) $with
public function getConnectionName(): ?string
public function getTable(): string
public function identifier(): string
public function newQueryForRestoration(mixed $ids): Illuminate\Database\Eloquent\Builder
@param (int | string | array<array-key, (int | string)>) $ids
@return Builder<static>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\OwnerMembership>
public final static function ownershipDefinition(): Nvl\Support\Ownership\ValueObjects\OwnershipDefinition
public function refresh(): static
public function refreshForUpdate(): static
public function save(array $options=[]): bool
@param array<string, mixed> $options
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $id
@property bool $is_owner
@property (string | null) $owner_reference
@property (string | null) $owner_scope_key
@property int $revision
@property MembershipStatus $status
resolved @property Nvl\Auth\Enums\MembershipStatus $status
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\Passkey

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\PasskeyFactory::class)]
final class Nvl\Auth\Models\Passkey extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Passkeys
public function getConnectionName(): ?string
public function identifier(): string
@property bool $backed_up
@property bool $backup_eligible
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $credential_id
@property string $credential_id_hash
@property string $id
@property (CarbonImmutable | null) $last_used_at
resolved @property (Carbon\CarbonImmutable | null) $last_used_at
@property (string | null) $name
@property string $public_key
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property int $signature_counter
@property string $subject_id
@property string $subject_type
@property (list<string> | null) $transports
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
@property string $user_handle
```

## Nvl\Auth\Models\PendingEmailChange

```text
final class Nvl\Auth\Models\PendingEmailChange extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::PendingEmailChanges
public function getConnectionName(): ?string
public function identifier(): string
@property (string | null) $active_key
@property (CarbonImmutable | null) $consumed_at
resolved @property (Carbon\CarbonImmutable | null) $consumed_at
@property array<string, mixed> $context
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $email_hash
@property CarbonImmutable $expires_at
resolved @property Carbon\CarbonImmutable $expires_at
@property string $id
@property string $new_email
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property int $security_revision
@property string $subject_id
@property string $subject_type
@property string $token_hash
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\Permission

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\PermissionFactory::class)]
class Nvl\Auth\Models\Permission extends Spatie\Permission\Models\Permission
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Permissions
public function getConnectionName(): ?string
public function getTable(): string
public function users(): Illuminate\Database\Eloquent\Relations\BelongsToMany
@return BelongsToMany<covariant Model, $this, covariant Pivot>
resolved @return Illuminate\Database\Eloquent\Relations\BelongsToMany<covariant Illuminate\Database\Eloquent\Model, $this, covariant Illuminate\Database\Eloquent\Relations\Pivot>
@property (string | null) $description
@property (string | null) $display_name
@property (string | null) $group
@property string $guard_name
@property string $id
@property bool $is_system
@property (array<string, mixed> | null) $metadata
@property string $name
@property-read (int | null) $roles_count
@property-read (int | null) $users_count
```

## Nvl\Auth\Models\PersonalAccessToken

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\PersonalAccessTokenFactory::class)]
class Nvl\Auth\Models\PersonalAccessToken extends Laravel\Sanctum\PersonalAccessToken implements Nvl\Support\Ownership\Contracts\Ownable
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::PersonalAccessTokens
public function delete(): mixed
@return ($this is Pivot ? (bool | int | null) : (bool | null))
resolved @return ($this is Illuminate\Database\Eloquent\Relations\Pivot ? (bool | int | null) : (bool | null))
public function fresh(mixed $with=[]): ?static
@param (array<array-key, mixed> | string) $with
public function getConnectionName(): ?string
public function getTable(): string
public function newQueryForRestoration(mixed $ids): Illuminate\Database\Eloquent\Builder
@param (int | string | array<array-key, (int | string)>) $ids
@return Builder<static>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\PersonalAccessToken>
public static function ownershipDefinition(): Nvl\Support\Ownership\ValueObjects\OwnershipDefinition
public function refresh(): static
public function refreshForUpdate(): static
public function save(array $options=[]): bool
@param array<string, mixed> $options
@property (list<string> | null) $abilities
@property string $id
@property string $name
@property (string | null) $owner_reference
@property (string | null) $owner_scope_key
@property string $token
@property string $tokenable_id
@property string $tokenable_type
```

## Nvl\Auth\Models\RecoveryCode

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\RecoveryCodeFactory::class)]
final class Nvl\Auth\Models\RecoveryCode extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::RecoveryCodes
public function getConnectionName(): ?string
public function identifier(): string
@property string $batch_id
@property string $code_hash
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $id
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
@property (CarbonImmutable | null) $used_at
resolved @property (Carbon\CarbonImmutable | null) $used_at
```

## Nvl\Auth\Models\RememberCredential

```text
final class Nvl\Auth\Models\RememberCredential extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::RememberCredentials
public function getConnectionName(): ?string
public function identifier(): string
@property CarbonImmutable $absolute_expires_at
resolved @property Carbon\CarbonImmutable $absolute_expires_at
@property (CarbonImmutable | null) $consumed_at
resolved @property (Carbon\CarbonImmutable | null) $consumed_at
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property string $guard_name
@property string $id
@property string $provider_hash
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property (string | null) $rotated_to_id
@property string $secret_hash
@property int $security_revision
@property string $selector
@property string $session_family_id
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\Role

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\RoleFactory::class)]
class Nvl\Auth\Models\Role extends Spatie\Permission\Models\Role implements Nvl\Support\Ownership\Contracts\Ownable
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Roles
public function children(): Illuminate\Database\Eloquent\Relations\HasMany
@return HasMany<static, $this>
resolved @return Illuminate\Database\Eloquent\Relations\HasMany<Nvl\Auth\Models\Role, $this>
public function delete(): mixed
@return ($this is Pivot ? (bool | int | null) : (bool | null))
resolved @return ($this is Illuminate\Database\Eloquent\Relations\Pivot ? (bool | int | null) : (bool | null))
public function fresh(mixed $with=[]): ?static
@param (array<array-key, mixed> | string) $with
public function getConnectionName(): ?string
public function getTable(): string
public function newQueryForRestoration(mixed $ids): Illuminate\Database\Eloquent\Builder
@param (int | string | array<array-key, (int | string)>) $ids
@return Builder<static>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\Role>
public static function ownershipDefinition(): Nvl\Support\Ownership\ValueObjects\OwnershipDefinition
public function parent(): Illuminate\Database\Eloquent\Relations\BelongsTo
@return BelongsTo<static, $this>
resolved @return Illuminate\Database\Eloquent\Relations\BelongsTo<Nvl\Auth\Models\Role, $this>
public function refresh(): static
public function refreshForUpdate(): static
public function save(array $options=[]): bool
@param array<string, mixed> $options
public function users(): Illuminate\Database\Eloquent\Relations\BelongsToMany
@return BelongsToMany<covariant Model, $this, covariant Pivot>
resolved @return Illuminate\Database\Eloquent\Relations\BelongsToMany<covariant Illuminate\Database\Eloquent\Model, $this, covariant Illuminate\Database\Eloquent\Relations\Pivot>
@property (string | null) $description
@property (string | null) $display_name
@property string $guard_name
@property string $id
@property bool $is_system
@property (array<string, mixed> | null) $metadata
@property string $name
@property (string | null) $owner_reference
@property (string | null) $owner_scope_key
@property (string | null) $parent_id
@property-read (int | null) $permissions_count
@property int $priority
@property-read (int | null) $users_count
```

## Nvl\Auth\Models\SocialIdentity

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\SocialIdentityFactory::class)]
final class Nvl\Auth\Models\SocialIdentity extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::SocialIdentities
public function getConnectionName(): ?string
public function identifier(): string
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property (string | null) $email
@property string $id
@property (CarbonImmutable | null) $last_used_at
resolved @property (Carbon\CarbonImmutable | null) $last_used_at
@property (array<string, mixed> | null) $profile
@property string $provider
@property string $provider_user_id
@property string $provider_user_id_hash
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\TotpCredential

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\TotpCredentialFactory::class)]
final class Nvl\Auth\Models\TotpCredential extends Nvl\Auth\Models\AuthModel
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::TotpCredentials
public function getConnectionName(): ?string
public function identifier(): string
@property string $algorithm
@property int $allowed_drift
@property (CarbonImmutable | null) $confirmed_at
resolved @property (Carbon\CarbonImmutable | null) $confirmed_at
@property (CarbonImmutable | null) $created_at
resolved @property (Carbon\CarbonImmutable | null) $created_at
@property int $digits
@property string $id
@property (int | null) $last_accepted_timestep
@property (CarbonImmutable | null) $last_used_at
resolved @property (Carbon\CarbonImmutable | null) $last_used_at
@property (string | null) $name
@property int $period
@property (CarbonImmutable | null) $revoked_at
resolved @property (Carbon\CarbonImmutable | null) $revoked_at
@property string $secret
@property string $subject_id
@property string $subject_type
@property (CarbonImmutable | null) $updated_at
resolved @property (Carbon\CarbonImmutable | null) $updated_at
```

## Nvl\Auth\Models\User

```text
#[Illuminate\Database\Eloquent\Attributes\UseFactory(\Nvl\Auth\Database\Factories\UserFactory::class)]
class Nvl\Auth\Models\User extends Illuminate\Foundation\Auth\User implements Illuminate\Contracts\Auth\CanResetPassword, Illuminate\Contracts\Auth\MustVerifyEmail, Illuminate\Contracts\Translation\HasLocalePreference
public const mixed TABLE=\Nvl\Auth\Definitions\Tables\AuthTables::Users
public function __construct(array $attributes=[]): mixed
@param array<string, mixed> $attributes
public function acceptedInvitations(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<Invitation, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\Invitation, $this>
public function authAudits(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<AuthAudit, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\AuthAudit, $this>
public function authChallenges(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<Challenge, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\Challenge, $this>
public function authClientSessions(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<AuthClientSession, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\AuthClientSession, $this>
public function getAuthPasswordName(): string
public function getConnectionName(): ?string
public function getCreatedAtColumn(): ?string
public function getDeletedAtColumn(): string
public function getEmailForPasswordReset(): string
public function getEmailForVerification(): string
public function getEmailIdentityHashName(): string
public function getFillable(): array
@return list<string>
public function getHidden(): array
@return list<string>
public function getKeyName(): string
public function getRememberTokenName(): string
public function getTable(): string
public function getUpdatedAtColumn(): ?string
public function hasVerifiedEmail(): bool
public function isAuthenticationAllowed(): bool
public function markEmailAsVerified(): bool
public function passkeys(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<Passkey, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\Passkey, $this>
public function performedAuthAudits(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<AuthAudit, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\AuthAudit, $this>
public function preferredLocale(): string
public function recoveryCodes(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<RecoveryCode, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\RecoveryCode, $this>
public function save(array $options=[]): bool
public function scopeAuthenticationAllowed(Illuminate\Database\Eloquent\Builder $query): Illuminate\Database\Eloquent\Builder
@param Builder<User> $query
resolved @param Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\User> $query
@return Builder<User>
resolved @return Illuminate\Database\Eloquent\Builder<Nvl\Auth\Models\User>
public function sentInvitations(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<Invitation, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\Invitation, $this>
public function socialIdentities(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<SocialIdentity, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\SocialIdentity, $this>
public function totpCredentials(): Illuminate\Database\Eloquent\Relations\MorphMany
@return MorphMany<TotpCredential, $this>
resolved @return Illuminate\Database\Eloquent\Relations\MorphMany<Nvl\Auth\Models\TotpCredential, $this>
@property (CarbonImmutable | null) $deleted_at
resolved @property (Carbon\CarbonImmutable | null) $deleted_at
@property string $email
@property (CarbonImmutable | null) $email_verified_at
resolved @property (Carbon\CarbonImmutable | null) $email_verified_at
@property string $id
@property bool $is_active
@property (CarbonImmutable | null) $last_login_at
resolved @property (Carbon\CarbonImmutable | null) $last_login_at
@property (string | null) $last_login_ip
@property string $locale
@property (CarbonImmutable | null) $locked_until
resolved @property (Carbon\CarbonImmutable | null) $locked_until
@property string $name
@property (string | null) $password
@property (array<string, mixed> | null) $preferences
@property (array<string, mixed> | null) $profile
@property (string | null) $remember_token
@property string $timezone
```

## Nvl\Auth\Ownership\AuthOwnerAccess

```text
final readonly class Nvl\Auth\Ownership\AuthOwnerAccess implements Nvl\Ownership\Contracts\OwnerAccess
public function __construct(Nvl\Ownership\Services\OwnerIdentityResolver $owners, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Contracts\MembershipPrincipalResolver $principals, Nvl\Support\Ownership\Contracts\OwnershipReadiness $readiness): mixed
public function assertCanEnter(Illuminate\Contracts\Auth\Authenticatable $actor, Illuminate\Database\Eloquent\Model $owner): void
```

## Nvl\Auth\Results\GeneratedRecoveryCodes

```text
final readonly class Nvl\Auth\Results\GeneratedRecoveryCodes
public function __construct(string $batchId, array $codes): mixed
@param list<string> $codes
public function __debugInfo(): array
@return array{batch_id: string, code_count: int}
public readonly string $batchId
public readonly array $codes
@param list<string> $codes
```

## Nvl\Auth\Results\IssuedApiToken

```text
final readonly class Nvl\Auth\Results\IssuedApiToken
public function __construct(array $token, string $plainTextToken): mixed
@param array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable} $token
resolved @param array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable} $token
public function __debugInfo(): array
@return array{token_id: string, plain_text_token: string}
public readonly string $plainTextToken
public readonly array $token
@param array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable} $token
resolved @param array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable} $token
```

## Nvl\Auth\Results\TotpEnrollment

```text
final readonly class Nvl\Auth\Results\TotpEnrollment
public function __construct(Nvl\Auth\Models\TotpCredential $credential, string $secret, string $provisioningUri): mixed
public function __debugInfo(): array
@return array{credential_id: string, secret: string, provisioning_uri: string}
public readonly Nvl\Auth\Models\TotpCredential $credential
public readonly string $provisioningUri
public readonly string $secret
```

## Nvl\Auth\Services\AuthAccountRecovery

```text
final readonly class Nvl\Auth\Services\AuthAccountRecovery
public function __construct(Nvl\Auth\Services\UserLocator $users, Nvl\Auth\Services\MutationAuthorizer $authorization, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\UsableAccountAuthenticationPolicy $nativeRemoval, Nvl\Auth\Contracts\AccountAuthenticationPolicy $policy, Nvl\Auth\Contracts\PrincipalSessionContainment $containment, Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Support\Events\DomainEventDispatcher $events, Nvl\Auth\Services\AuthAccountSecurity $inventory, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes): mixed
public function recover(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\User|string $subject, array $changes): Nvl\Auth\Models\User
@param array<string, mixed> $changes
```

## Nvl\Auth\Services\AuthAccountSecurity

```text
final readonly class Nvl\Auth\Services\AuthAccountSecurity
public function __construct(Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\SocialProviderRegistry $providers): mixed
public function state(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return array{hasPassword: bool, passkeys: list<array{id: string, name: ?string, lastUsedAt: ?CarbonImmutable}>, socialIdentities: list<array{id: string, provider: string}>, totpEnabled: bool, recoveryCodesRemaining: int}
resolved @return array{hasPassword: bool, passkeys: list<array{id: string, name: ?string, lastUsedAt: ?Carbon\CarbonImmutable}>, socialIdentities: list<array{id: string, provider: string}>, totpEnabled: bool, recoveryCodesRemaining: int}
```

## Nvl\Auth\Services\AuthAuditReader

```text
final readonly class Nvl\Auth\Services\AuthAuditReader
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Support\Ownership\Contracts\OwnershipBoundary $boundary): mixed
public function find(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\AuthAudit $audit): Nvl\Auth\Models\AuthAudit
public function paginate(Illuminate\Contracts\Auth\Authenticatable $actor, int $perPage=50): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, AuthAudit>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\AuthAudit>
```

## Nvl\Auth\Services\AuthBrowserSessions

```text
final readonly class Nvl\Auth\Services\AuthBrowserSessions
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\PrincipalEligibility $eligibility, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Contracts\AuthAuditRecorder $audits): mixed
public function admit(Illuminate\Contracts\Auth\Authenticatable $subject, string $guardName, #[SensitiveParameter()] string $binding): Nvl\Auth\Models\BrowserSession
public static function bindingKey(string $guardName): string
public function paginate(Illuminate\Contracts\Auth\Authenticatable $subject, string $guardName, int $perPage=25): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, BrowserSession>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\BrowserSession>
public function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, string $sessionId, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\BrowserSession
public function revokeAll(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): int
public function revokeOthers(Illuminate\Contracts\Auth\Authenticatable $subject, string $guardName, string $currentSessionId, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): int
```

## Nvl\Auth\Services\AuthChallenges

```text
final readonly class Nvl\Auth\Services\AuthChallenges
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthDeliveryContext $deliveryContext, Nvl\Auth\Contracts\AuthSubjectResolver $subjects, Nvl\Auth\Services\AuthenticationSessions $sessions, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\OpaqueTokenFactory $tokens, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\PrincipalAttributeMapper $principalAttributes, Nvl\Auth\Contracts\AuthIdentifierResolver $identifiers, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\AuthCommittedAudit $committedAudits): mixed
public function consume(Nvl\Auth\Enums\AuthFeature $feature, Nvl\Auth\Enums\AuthMessageType $messageType, string $recipient, string $purpose, string $secret): Nvl\Auth\Models\Challenge
public function consumeById(Nvl\Auth\Enums\AuthFeature $feature, Nvl\Auth\Enums\AuthMessageType $messageType, string $challengeId, string $purpose, string $secret): Nvl\Auth\Models\Challenge
public function consumeMagicLink(array $data, string $purpose="login"): Nvl\Auth\Models\Challenge
@param array<string, mixed> $data
public function consumeMagicLinkAuthentication(#[SensitiveParameter()] array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
@param array<string, mixed> $data
public function issue(Nvl\Auth\Enums\AuthFeature $feature, Nvl\Auth\Enums\AuthMessageType $messageType, string $recipient, string $purpose, Carbon\CarbonImmutable $expiresAt, bool $numeric=false, int $digits=6, int $maxAttempts=5, ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, array $payload=[], array $metadata=[], ?string $locale=null, bool $withFallbackCode=false, int $fallbackDigits=6): array
@param array<string, mixed> $payload
@param array<string, mixed> $metadata
@return array{challenge: Challenge, secret: string, fallbackCode: (string | null)}
resolved @return array{challenge: Nvl\Auth\Models\Challenge, secret: string, fallbackCode: (string | null)}
public function proveSecurityCodeAuthentication(#[SensitiveParameter()] array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
@param array<string, mixed> $data
public function requestMagicLink(array $data, ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, array $payload=[], ?string $locale=null): array
@param array<string, mixed> $payload
@param array<string, mixed> $data
@return array{challenge: Challenge, secret: string, fallbackCode: (string | null)}
resolved @return array{challenge: Nvl\Auth\Models\Challenge, secret: string, fallbackCode: (string | null)}
public function requestMagicLinkAuthentication(array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, ?string $locale=null): ?array
@param array<string, mixed> $data
@return (array{challenge: Challenge, secret: string, fallbackCode: (string | null)} | null)
resolved @return (array{challenge: Nvl\Auth\Models\Challenge, secret: string, fallbackCode: (string | null)} | null)
public function requestSecurityCode(array $data, ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, array $payload=[], ?string $locale=null): array
@param array<string, mixed> $payload
@param array<string, mixed> $data
@return array{challenge: Challenge, secret: string, fallbackCode: (string | null)}
resolved @return array{challenge: Nvl\Auth\Models\Challenge, secret: string, fallbackCode: (string | null)}
public function requestSecurityCodeAuthentication(array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, ?string $locale=null): ?array
@param array<string, mixed> $data
@return (array{challenge: Challenge, secret: string, fallbackCode: (string | null)} | null)
resolved @return (array{challenge: Nvl\Auth\Models\Challenge, secret: string, fallbackCode: (string | null)} | null)
public function verifySecurityCode(array $data): Nvl\Auth\Models\Challenge
@param array<string, mixed> $data
public function verifySecurityCodeAuthentication(#[SensitiveParameter()] array $data, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Illuminate\Contracts\Auth\Authenticatable
@param array<string, mixed> $data
```

## Nvl\Auth\Services\AuthClients

```text
final readonly class Nvl\Auth\Services\AuthClients
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Pipelines\AuthPipeline $pipeline): mixed
public function create(Illuminate\Contracts\Auth\Authenticatable $actor, array $data): Nvl\Auth\Models\AuthClient
@param array<string, mixed> $data
public function delete(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\AuthClient $client): void
public function endSession(Nvl\Auth\Models\AuthClientSession $session, string $reason="logout"): Nvl\Auth\Models\AuthClientSession
public function find(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\AuthClient $client): Nvl\Auth\Models\AuthClient
public function paginate(Illuminate\Contracts\Auth\Authenticatable $actor, int $perPage=25): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, AuthClient>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\AuthClient>
public function recordSession(Nvl\Auth\Models\AuthClient $client, string $sessionId, ?Illuminate\Contracts\Auth\Authenticatable $subject=null, ?string $ipAddress=null, ?string $userAgent=null, array $metadata=[]): Nvl\Auth\Models\AuthClientSession
@param array<string, mixed> $metadata
public function setActive(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\AuthClient $client, bool $active): Nvl\Auth\Models\AuthClient
public function start(array $data): array
@param array<string, mixed> $data
@return array<string, mixed>
public function touchSession(string $clientId, string $sessionId): Nvl\Auth\Models\AuthClientSession
public function update(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\AuthClient $client, array $data): Nvl\Auth\Models\AuthClient
@param array<string, mixed> $data
```

## Nvl\Auth\Services\AuthEmailChanges

```text
final readonly class Nvl\Auth\Services\AuthEmailChanges
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Support\Events\DomainEventDispatcher $events, Nvl\Auth\Services\AuthDeliveryContext $delivery, Nvl\Auth\Services\AuthConfiguration $configuration): mixed
public function cancel(Illuminate\Contracts\Auth\Authenticatable $subject, string $changeId): void
public function complete(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] string $token, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\User
public function request(Illuminate\Contracts\Auth\Authenticatable $subject, string $newEmail, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\PendingEmailChange
```

## Nvl\Auth\Services\AuthEmailVerification

```text
final readonly class Nvl\Auth\Services\AuthEmailVerification
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthDeliveryContext $deliveryContext, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Support\Events\ConnectionCommitCallbacks $eventCommits, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\SecretHasher $hasher): mixed
public function request(Illuminate\Contracts\Auth\Authenticatable&Illuminate\Contracts\Auth\MustVerifyEmail $subject, ?string $locale=null): void
public function verify(Illuminate\Contracts\Auth\Authenticatable&Illuminate\Contracts\Auth\MustVerifyEmail $subject, #[SensitiveParameter()] string $token): bool
```

## Nvl\Auth\Services\AuthExecutionContext

```text
final class Nvl\Auth\Services\AuthExecutionContext
public function __construct(Illuminate\Contracts\Container\Container $container): mixed
public function __serialize(): never
public function assertNativeMutationAllowed(): void
public function facts(): ?array
@return (array{actor_type: string, actor_id: string, effective_subject_type: string, effective_subject_id: string, impersonation_id: string} | null)
public function run(Illuminate\Contracts\Auth\Authenticatable $actor, string $impersonationId, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, Closure $callback): mixed
@template TResult
@param Closure(Authenticatable, Authenticatable): TResult $callback
resolved @param Closure(Illuminate\Contracts\Auth\Authenticatable, Illuminate\Contracts\Auth\Authenticatable): TResult $callback
@return TResult
template Nvl\Auth\Services\AuthExecutionContext::TResult
```

## Nvl\Auth\Services\AuthImpersonation

```text
final readonly class Nvl\Auth\Services\AuthImpersonation
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthenticationSessions $transitions, Nvl\Auth\Services\AuthBrowserSessions $sessions, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Contracts\AuthSubjectResolver $subjects, Nvl\Auth\Services\PrincipalEligibility $eligibility, Nvl\Auth\Contracts\ImpersonationAccess $access, Nvl\Support\Ownership\Contracts\OwnershipContext $ownership, Nvl\Auth\Services\AuthOwnerAdmission $owners, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\MutationAuthorizer $management, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Support\Events\DomainEventDispatcher $events): mixed
public function admit(Illuminate\Contracts\Auth\Authenticatable $actor, string $impersonationId, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@return array{grant: Impersonation, actor: (Model & Authenticatable), target: (Model & Authenticatable)}
resolved @return array{grant: Nvl\Auth\Models\Impersonation, actor: (Illuminate\Database\Eloquent\Model & Illuminate\Contracts\Auth\Authenticatable), target: (Illuminate\Database\Eloquent\Model & Illuminate\Contracts\Auth\Authenticatable)}
public function revoke(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, string $impersonationId, string $reason): Nvl\Auth\Models\Impersonation
public function start(Illuminate\Contracts\Auth\Authenticatable $actor, Illuminate\Contracts\Auth\Authenticatable $target, #[SensitiveParameter()] string $recentProof, array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\Impersonation
@param array<string, mixed> $data
public function stop(Illuminate\Contracts\Auth\Authenticatable $actor, string $impersonationId, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, string $reason="requested"): Nvl\Auth\Models\Impersonation
```

## Nvl\Auth\Services\AuthInvitations

```text
final readonly class Nvl\Auth\Services\AuthInvitations
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthDeliveryContext $deliveryContext, Nvl\Auth\Services\MutationAuthorizer $mutations, Nvl\Auth\Services\OwnerInvitations $owned, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Contracts\InvitationRecipientProof $recipientProof, Illuminate\Contracts\Container\Container $container, Nvl\Support\Ownership\Contracts\OwnershipBoundary $boundary, Nvl\Auth\Services\OwnerMembershipAssignments $assignments, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthCommittedAudit $committedAudits, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Support\Ownership\Contracts\OwnershipContext $ownerContext, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\OpaqueTokenFactory $tokens, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\PasswordValidationRules $passwordPolicy, Nvl\Auth\Services\InvitationPrincipalResolver $principalResolver, ?Nvl\Auth\Services\InvitationDeliveryMetadataPolicy $deliveryMetadata=null): mixed
public function accept(string $token, Illuminate\Contracts\Auth\Authenticatable $subject): Nvl\Auth\Models\Invitation
public function create(#[SensitiveParameter()] array $data, Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, ?Nvl\Auth\ValueObjects\InvitationIssuanceContext $context=null): array
@param array<string, mixed> $data
@return array<string, mixed>
public function findActive(string $recipient, string $purpose, ?array $types=null, ?string $context=null, Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext|null $authority=null): ?Nvl\Auth\Models\Invitation
@param (list<string> | null) $types
public function paginate(Illuminate\Contracts\Auth\Authenticatable $actor, array $filters=[], int $perPage=25): Illuminate\Pagination\LengthAwarePaginator
@param array<string, mixed> $filters
@return LengthAwarePaginator<int, Invitation>
resolved @return Illuminate\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\Invitation>
public function preview(string $token): Nvl\Auth\Models\Invitation
public function recordDeliveryOutcome(string $invitationId, string $messageId, Nvl\Auth\Enums\InvitationDeliveryStatus $status, Carbon\CarbonImmutable $occurredAt, ?string $failureCode=null): void
public function register(#[SensitiveParameter()] array $data, ?Illuminate\Contracts\Auth\Authenticatable $authenticatedRecipient=null): array
@param array<string, mixed> $data
@return array<string, mixed>
public function registerSocial(#[SensitiveParameter()] string $invitationToken, #[SensitiveParameter()] string $continuation, array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@param array<string, mixed> $data
@return array{invitation: Invitation, subject: User}
resolved @return array{invitation: Nvl\Auth\Models\Invitation, subject: Nvl\Auth\Models\User}
public function resend(Nvl\Auth\Models\Invitation|string $invitation, Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, ?string $locale=null, ?Nvl\Auth\ValueObjects\InvitationIssuanceContext $context=null): array
@return array<string, mixed>
public function revoke(Nvl\Auth\Models\Invitation|string $invitation, Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority): Nvl\Auth\Models\Invitation
```

## Nvl\Auth\Services\AuthMaintenance

```text
final readonly class Nvl\Auth\Services\AuthMaintenance
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\PrincipalAdoptionManifest $manifests, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\MutationAuthorizer $mutations): mixed
public function adoptPrincipals(array $manifest, Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, bool $stage=false, bool $apply=false): array
@param array<array-key, mixed> $manifest
@return array<string, mixed>
public function prune(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, bool $dryRun=false): array
@return array<string, int>
```

## Nvl\Auth\Services\AuthMemberships

```text
final readonly class Nvl\Auth\Services\AuthMemberships
public function __construct(Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\ManagementAuthorizer $management, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Support\Ownership\Contracts\OwnershipReadiness $readiness, Nvl\Support\Ownership\Contracts\OwnershipBoundary $boundary, Nvl\Support\Ownership\Contracts\OwnershipContext $context, Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\MutationAuthorizer $authorization, Nvl\Auth\Contracts\MembershipPrincipalResolver $principals, Nvl\Auth\Services\OwnerMembershipAssignments $assignments, Nvl\Auth\Services\AuthCommittedAudit $audits): mixed
public function assertPrincipalCanBeDisabled(Nvl\Auth\ValueObjects\SubjectReference $subject): void
public function enroll(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\ValueObjects\SubjectReference $subject, array $roles=[], array $permissions=[]): Nvl\Auth\Models\OwnerMembership
@param list<string> $roles
@param list<string> $permissions
public function find(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Membership|string $membership): Nvl\Auth\Models\OwnerMembership
public function lock(bool $prepare=false): void
public function own(Illuminate\Contracts\Auth\Authenticatable $subject): Illuminate\Support\Collection
@return Collection<int, array{owner: array{version: int, type: string, storage: string, keyType: string, key: string}, membership_id: string, status: MembershipStatus, revision: int}>
resolved @return Illuminate\Support\Collection<int, array{owner: array{version: int, type: string, storage: string, keyType: string, key: string}, membership_id: string, status: Nvl\Auth\Enums\MembershipStatus, revision: int}>
public function paginate(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, int $perPage=25): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, OwnerMembership>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\OwnerMembership>
public function provision(Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\ValueObjects\SubjectReference $subject): Nvl\Auth\Models\OwnerMembership
public function revoke(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\Membership|string $membership, int $expectedRevision): Nvl\Auth\Models\OwnerMembership
public function setStatus(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\Membership|string $membership, Nvl\Auth\Enums\MembershipStatus $status, int $expectedRevision): Nvl\Auth\Models\OwnerMembership
public function transfer(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\Membership|string $membership, string $recipientId, int $expectedRevision): Nvl\Auth\Models\OwnerMembership
```

## Nvl\Auth\Services\AuthOwnerAdmission

```text
final readonly class Nvl\Auth\Services\AuthOwnerAdmission
public function __construct(Illuminate\Container\Container $container, Nvl\Support\Ownership\Contracts\OwnershipContext $context, Nvl\Auth\Contracts\MembershipPrincipalResolver $principals, Nvl\Support\Ownership\Contracts\OwnershipReadiness $readiness, Nvl\Auth\Services\AuthOwnershipState $state): mixed
public function assertAllowed(Illuminate\Contracts\Auth\Authenticatable $subject): void
```

## Nvl\Auth\Services\AuthPasskeys

```text
final readonly class Nvl\Auth\Services\AuthPasskeys
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthConfiguration $configuration, Illuminate\Contracts\Container\Container $container, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\OwnerAuthenticationChallengeIntents $ownerIntents, Nvl\Auth\Services\PasskeyInputValidator $input, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Contracts\AuthSubjectResolver $subjects, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\UsableAccountAuthenticationPolicy $nativeRemoval, Nvl\Auth\Contracts\AccountAuthenticationPolicy $removalPolicy, Nvl\Support\Events\DomainEventDispatcher $securityEvents): mixed
public function beginAuthentication(?Illuminate\Contracts\Auth\Authenticatable $subject=null, ?Nvl\Support\Ownership\ValueObjects\OwnerReference $owner=null, ?string $sessionBinding=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\ValueObjects\PasskeyCeremonyOptions
public function beginReauthentication(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\PasskeyCeremonyOptions
public function beginRegistration(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\ValueObjects\PasskeyCeremonyOptions
public function finishAuthentication(#[SensitiveParameter()] array $data, ?Nvl\Support\Ownership\ValueObjects\OwnerReference $requestedOwner=null, ?string $sessionBinding=null): array
@param array<string, mixed> $data
@return array{subject: SubjectReference, proof: IssuedAuthenticationProof, requestContext: AuthenticationRequestContext}
resolved @return array{subject: Nvl\Auth\ValueObjects\SubjectReference, proof: Nvl\Auth\ValueObjects\IssuedAuthenticationProof, requestContext: Nvl\Auth\ValueObjects\AuthenticationRequestContext}
public function finishRegistration(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Models\Passkey
@param array<string, mixed> $data
public function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\Models\Passkey $passkey, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Models\Passkey
```

## Nvl\Auth\Services\AuthPasswords

```text
final readonly class Nvl\Auth\Services\AuthPasswords
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthDeliveryContext $deliveryContext, Illuminate\Contracts\Hashing\Hasher $hasher, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\PrincipalAttributeMapper $principalAttributes, Illuminate\Auth\Passwords\PasswordBrokerManager $brokers, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Contracts\AuthenticationEligibility $eligibility, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Contracts\PasswordUpdater $passwords, Nvl\Support\Events\ConnectionCommitCallbacks $eventCommits, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PasswordValidationRules $policy, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\PrincipalEmailIdentity $emails, Nvl\Auth\Services\UsableAccountAuthenticationPolicy $nativeRemoval, Nvl\Auth\Contracts\AccountAuthenticationPolicy $removalPolicy): mixed
public function confirm(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data, Illuminate\Contracts\Session\Session $session): void
@param array<string, mixed> $data
public function remove(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): void
public function requestReset(array $data, ?string $locale=null): void
@param array<string, mixed> $data
public function reset(#[SensitiveParameter()] array $data): void
@param array<string, mixed> $data
public function setInitial(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): void
@param array<string, mixed> $data
public function update(Illuminate\Contracts\Auth\Authenticatable&Illuminate\Contracts\Auth\CanResetPassword $subject, #[SensitiveParameter()] array $data, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): void
@param array<string, mixed> $data
```

## Nvl\Auth\Services\AuthPermissions

```text
final readonly class Nvl\Auth\Services\AuthPermissions
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthCommittedAudit $committedAudits, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Services\RbacAssignmentService $assignments, Nvl\Auth\Services\RbacEntityLocator $entities, Nvl\Auth\Services\RbacSynchronizer $synchronizer, Illuminate\Container\Container $rbacContainer, Nvl\Auth\Services\MutationAuthorizer $syncUserPermissionsAuthorization, Nvl\Auth\Contracts\RbacPrincipalAccess $principals, Nvl\Auth\Services\RbacManager $rbac, Nvl\Auth\Services\MutationAuthorizer $bootstrapAuthorization): mixed
public function bootstrap(Nvl\Auth\ValueObjects\SystemMutationContext $context): array
@return array<string, mixed>
public function create(Illuminate\Contracts\Auth\Authenticatable $actor, array $data): Nvl\Auth\Models\Permission
@param array<string, mixed> $data
public function createWithRoles(Illuminate\Contracts\Auth\Authenticatable $actor, array $data, array $roleIdentifiers=[]): Nvl\Auth\Models\Permission
@param list<string> $roleIdentifiers
@param array<string, mixed> $data
public function delete(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Permission|string $permission): bool
public function synchronize(Illuminate\Contracts\Auth\Authenticatable $actor): array
@return array<string, mixed>
public function synchronizeCatalog(Illuminate\Contracts\Auth\Authenticatable $actor): int
public function syncUserPermissions(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Illuminate\Contracts\Auth\Authenticatable|string $user, array $data): Illuminate\Contracts\Auth\Authenticatable
@param array<string, mixed> $data
public function update(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Permission|string $permission, array $data): Nvl\Auth\Models\Permission
@param array<string, mixed> $data
```

## Nvl\Auth\Services\AuthRbacReader

```text
final readonly class Nvl\Auth\Services\AuthRbacReader
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\RbacPermissionGroupExpressions $groupExpressions, Nvl\Auth\Services\RbacConsumerLimits $limits, Nvl\Auth\Services\RbacOptionReadService $options, Nvl\Auth\Services\RoleHierarchy $hierarchy, Nvl\Auth\Services\RoleTemplateRegistry $templates, Nvl\Auth\Services\RbacEntityLocator $entities, Nvl\Auth\Contracts\PrincipalAttributeMapper $principalAttributes): mixed
public function analytics(Illuminate\Contracts\Auth\Authenticatable $actor): array
@return array<string, mixed>
public function permission(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Permission|string $permission): Nvl\Auth\Models\Permission
public function permissionCatalog(Illuminate\Contracts\Auth\Authenticatable $actor, array $data): Illuminate\Contracts\Pagination\LengthAwarePaginator
@param array<string, mixed> $data
@return LengthAwarePaginator<int, Permission>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\Permission>
public function permissionGroups(Illuminate\Contracts\Auth\Authenticatable $actor): Illuminate\Support\Collection
@return Collection<int, array{value: string, label: string, permissionsCount: int}>
resolved @return Illuminate\Support\Collection<int, array{value: string, label: string, permissionsCount: int}>
public function permissionOptions(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, ?string $group=null, ?int $limit=null): Illuminate\Support\Collection
@return Collection<int, Permission>
resolved @return Illuminate\Support\Collection<int, Nvl\Auth\Models\Permission>
public function permissions(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, ?string $group=null, int $perPage=25): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, Permission>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\Permission>
public function resolvePermissions(Illuminate\Contracts\Auth\Authenticatable $actor, array $identifiers): Illuminate\Support\Collection
@param list<string> $identifiers
@return Collection<int, Permission>
resolved @return Illuminate\Support\Collection<int, Nvl\Auth\Models\Permission>
public function resolveRoles(Illuminate\Contracts\Auth\Authenticatable $actor, array $identifiers): Illuminate\Support\Collection
@param list<string> $identifiers
@return Collection<int, Role>
resolved @return Illuminate\Support\Collection<int, Nvl\Auth\Models\Role>
public function role(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role): Nvl\Auth\Models\Role
public function roleAnalytics(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role): array
@return array<string, mixed>
public function roleCatalog(Illuminate\Contracts\Auth\Authenticatable $actor, array $data): Illuminate\Contracts\Pagination\LengthAwarePaginator
@param array<string, mixed> $data
@return LengthAwarePaginator<int, Role>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\Role>
public function roleHierarchy(Illuminate\Contracts\Auth\Authenticatable $actor): array
@return list<array{id: string, name: string, display_name: (string | null), priority: int, user_count: int, children: list<mixed>}>
public function roleNameAvailability(Illuminate\Contracts\Auth\Authenticatable $actor, string $name, ?string $exceptId=null): array
@return array<string, mixed>
public function roleOptions(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, ?int $limit=null): Illuminate\Support\Collection
@return Collection<int, Role>
resolved @return Illuminate\Support\Collection<int, Nvl\Auth\Models\Role>
public function roles(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, int $perPage=25): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, Role>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\Role>
public function roleTemplates(Illuminate\Contracts\Auth\Authenticatable $actor): array
@return list<array<string, mixed>>
public function suggestPermissions(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, ?string $group=null, ?int $limit=null): Illuminate\Support\Collection
@return Collection<int, Permission>
resolved @return Illuminate\Support\Collection<int, Nvl\Auth\Models\Permission>
public function suggestRoles(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, ?int $limit=null): Illuminate\Support\Collection
@return Collection<int, Role>
resolved @return Illuminate\Support\Collection<int, Nvl\Auth\Models\Role>
```

## Nvl\Auth\Services\AuthReauthentication

```text
final readonly class Nvl\Auth\Services\AuthReauthentication
public function __construct(Nvl\Auth\Services\Authentication $authentication, Nvl\Auth\Services\AuthenticationProofs $proofs, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\StatefulAuthenticationBoundary $boundary, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\AuthBrowserSessions $browserSessions): mixed
public function confirm(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $proof, Nvl\Auth\Enums\RecentAuthenticationPurpose $purpose, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedRecentAuthentication
@param array{password?: mixed, code?: mixed, recoveryCode?: mixed, passkeyProof?: mixed, socialProof?: mixed} $proof
```

## Nvl\Auth\Services\AuthRegistration

```text
final readonly class Nvl\Auth\Services\AuthRegistration
public function __construct(Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\ConfiguredRegistrationAdmission $nativeAdmission, Nvl\Auth\Contracts\RegistrationAdmission $admission, Nvl\Auth\Services\PrincipalExtensions $extensions, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes, Nvl\Auth\Services\PasswordValidationRules $passwordPolicy, Nvl\Auth\Contracts\PasswordUpdater $passwords, Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\AuthCommittedAudit $audits, Nvl\Support\Events\DomainEventDispatcher $events, Nvl\Auth\Services\AuthEmailVerification $verification, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Services\SocialRegistrationContinuations $social, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\AuthIdentityChallenges $records): mixed
public function register(#[SensitiveParameter()] array $data): Nvl\Auth\Models\User
@param array<string, mixed> $data
public function registerInvitedSocial(#[SensitiveParameter()] string $invitationToken, #[SensitiveParameter()] string $continuation, array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@param array<string, mixed> $data
@return array{invitation: Invitation, subject: User}
resolved @return array{invitation: Nvl\Auth\Models\Invitation, subject: Nvl\Auth\Models\User}
public function registerSocial(#[SensitiveParameter()] string $continuation, array $data, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\User
@param array<string, mixed> $data
public function requestSocialEmailVerification(#[SensitiveParameter()] string $continuation, string $email, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): void
public function verifySocialEmail(#[SensitiveParameter()] string $continuation, #[SensitiveParameter()] string $code, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedSocialRegistration
```

## Nvl\Auth\Services\AuthRememberCredentials

```text
final readonly class Nvl\Auth\Services\AuthRememberCredentials
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Contracts\AuthSubjectResolver $subjects, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalEligibility $eligibility): mixed
public function resume(string $selector, #[SensitiveParameter()] string $secret, string $guardName, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
```

## Nvl\Auth\Services\AuthRoles

```text
final readonly class Nvl\Auth\Services\AuthRoles
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\RbacEntityLocator $entities, Nvl\Auth\Services\RoleHierarchy $hierarchy, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthCommittedAudit $committedAudits, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Services\RbacAssignmentService $assignments, Nvl\Auth\Services\RoleTemplateRegistry $templates, Nvl\Auth\Services\RbacSynchronizer $synchronizer, Illuminate\Container\Container $rbacContainer, Nvl\Auth\Services\MutationAuthorizer $syncUserRolesAuthorization, Nvl\Auth\Contracts\RbacPrincipalAccess $principals, Nvl\Auth\Services\RbacManager $rbac): mixed
public function addPermissions(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role, array $permissionIdentifiers): Nvl\Auth\Models\Role
@param list<string> $permissionIdentifiers
public function applyTemplate(Illuminate\Contracts\Auth\Authenticatable $actor, array $data): Nvl\Auth\Models\Role
@param array<string, mixed> $data
public function create(Illuminate\Contracts\Auth\Authenticatable $actor, array $data): Nvl\Auth\Models\Role
@param array<string, mixed> $data
public function delete(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role): bool
public function duplicate(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role, string $name, ?string $displayName=null): Nvl\Auth\Models\Role
public function synchronizeTemplates(Illuminate\Contracts\Auth\Authenticatable $actor): int
public function syncPermissions(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role, array $permissionIdentifiers): Nvl\Auth\Models\Role
@param list<string> $permissionIdentifiers
public function syncUserRoles(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Illuminate\Contracts\Auth\Authenticatable|string $user, array $data): Illuminate\Contracts\Auth\Authenticatable
@param array<string, mixed> $data
public function update(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\Role|string $role, array $data): Nvl\Auth\Models\Role
@param array<string, mixed> $data
```

## Nvl\Auth\Services\AuthSecondFactor

```text
final readonly class Nvl\Auth\Services\AuthSecondFactor
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\TotpEngine $totp, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\UsableAccountAuthenticationPolicy $nativeRemoval, Nvl\Auth\Contracts\AccountAuthenticationPolicy $removalPolicy, Nvl\Support\Events\DomainEventDispatcher $securityEvents): mixed
public function confirmEnrollment(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\Models\TotpCredential $credential, #[SensitiveParameter()] array $data, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Models\TotpCredential
@param array<string, mixed> $data
public function consumeRecoveryCode(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data): Nvl\Auth\Models\RecoveryCode
@param array<string, mixed> $data
public function regenerateRecoveryCodes(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Results\GeneratedRecoveryCodes
public function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\Models\TotpCredential $credential, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Models\TotpCredential
public function revokeRecoveryCodes(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): int
public function startEnrollment(Illuminate\Contracts\Auth\Authenticatable $subject, array $data, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Results\TotpEnrollment
@param array<string, mixed> $data
public function state(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return array<string, mixed>
public function verify(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data): Nvl\Auth\Models\TotpCredential
@param array<string, mixed> $data
```

## Nvl\Auth\Services\AuthSocialAuthentication

```text
final readonly class Nvl\Auth\Services\AuthSocialAuthentication
public function __construct(Nvl\Auth\Services\SocialAuthenticationIntents $intents, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\SocialProviderRegistry $registry): mixed
public function beginLogin(string $provider, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, Nvl\Auth\Enums\AuthenticationDestination $destination=\Nvl\Auth\Enums\AuthenticationDestination::Session): array
@return array{url: string, intent: IssuedSocialIntent}
resolved @return array{url: string, intent: Nvl\Auth\ValueObjects\IssuedSocialIntent}
public function beginReauthentication(Illuminate\Contracts\Auth\Authenticatable $subject, string $provider, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@return array{url: string, intent: IssuedSocialIntent}
resolved @return array{url: string, intent: Nvl\Auth\ValueObjects\IssuedSocialIntent}
public function completeLogin(string $provider, #[SensitiveParameter()] string $intent, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@return (array{status: 'authenticated', subject: Authenticatable, proof: IssuedAuthenticationProof} | array{status: 'registration_required', continuation: IssuedSocialRegistration})
resolved @return (array{status: 'authenticated', subject: Illuminate\Contracts\Auth\Authenticatable, proof: Nvl\Auth\ValueObjects\IssuedAuthenticationProof} | array{status: 'registration_required', continuation: Nvl\Auth\ValueObjects\IssuedSocialRegistration})
public function completeReauthentication(Illuminate\Contracts\Auth\Authenticatable $subject, string $provider, #[SensitiveParameter()] string $intent, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
```

## Nvl\Auth\Services\AuthSocialLinks

```text
final readonly class Nvl\Auth\Services\AuthSocialLinks
public function __construct(Nvl\Auth\Services\SocialAuthenticationIntents $intents, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\UsableAccountAuthenticationPolicy $nativeRemoval, Nvl\Auth\Contracts\AccountAuthenticationPolicy $removalPolicy, Nvl\Support\Events\DomainEventDispatcher $securityEvents): mixed
public function beginLink(Illuminate\Contracts\Auth\Authenticatable $subject, string $provider, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@return array{url: string, intent: IssuedSocialIntent}
resolved @return array{url: string, intent: Nvl\Auth\ValueObjects\IssuedSocialIntent}
public function beginReconnect(Illuminate\Contracts\Auth\Authenticatable $subject, string $provider, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@return array{url: string, intent: IssuedSocialIntent}
resolved @return array{url: string, intent: Nvl\Auth\ValueObjects\IssuedSocialIntent}
public function completeLink(Illuminate\Contracts\Auth\Authenticatable $subject, string $provider, #[SensitiveParameter()] string $intent, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\SocialIdentity
public function completeReconnect(Illuminate\Contracts\Auth\Authenticatable $subject, string $provider, #[SensitiveParameter()] string $intent, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\SocialIdentity
public function unlink(Illuminate\Contracts\Auth\Authenticatable $subject, string $identityId, #[SensitiveParameter()] string $recentProof, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\Models\SocialIdentity
```

## Nvl\Auth\Services\AuthTokens

```text
final readonly class Nvl\Auth\Services\AuthTokens
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ApiTokenPolicy $policy, Nvl\Auth\Contracts\ApiTokenManager $tokens, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthCommittedAudit $committedAudits, Nvl\Auth\Services\AuthenticationProofs $proofs, Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder $loginMetadata, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Support\Events\ConnectionCommitCallbacks $commits, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\PrincipalAttributeMapper $principalAttributes): mixed
public function all(Illuminate\Contracts\Auth\Authenticatable $subject): array
@return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}>
resolved @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}>
public function authenticateFromProof(#[SensitiveParameter()] string $proof, array $token, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@param array{name: string, abilities: list<string>, expiresAt?: (CarbonImmutable | null)} $token
resolved @param array{name: string, abilities: list<string>, expiresAt?: (Carbon\CarbonImmutable | null)} $token
@return array{subject: Authenticatable, token: IssuedApiToken}
resolved @return array{subject: Illuminate\Contracts\Auth\Authenticatable, token: Nvl\Auth\Results\IssuedApiToken}
public function create(Illuminate\Contracts\Auth\Authenticatable $subject, array $data): Nvl\Auth\Results\IssuedApiToken
@param array<string, mixed> $data
public function revoke(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId): bool
public function revokeAll(Illuminate\Contracts\Auth\Authenticatable $subject): int
public function rotate(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): Nvl\Auth\Results\IssuedApiToken
@param array<string, mixed> $data
public function update(Illuminate\Contracts\Auth\Authenticatable $subject, string $tokenId, array $data): array
@param array<string, mixed> $data
@return array{id: string, name: string, abilities: list<string>, lastUsedAt: (CarbonImmutable | null), expiresAt: (CarbonImmutable | null), createdAt: CarbonImmutable}
resolved @return array{id: string, name: string, abilities: list<string>, lastUsedAt: (Carbon\CarbonImmutable | null), expiresAt: (Carbon\CarbonImmutable | null), createdAt: Carbon\CarbonImmutable}
```

## Nvl\Auth\Services\AuthUserReader

```text
final readonly class Nvl\Auth\Services\AuthUserReader
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\ManagementAuthorizer $authorization, Nvl\Auth\Services\UserLocator $users, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes, Nvl\Auth\Services\AuthOperationBoundary $operations): mixed
public function find(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\User|string $user): Nvl\Auth\Models\User
public function paginate(Illuminate\Contracts\Auth\Authenticatable $actor, ?string $search=null, ?bool $active=null, string $trashed="without", ?string $role=null, int $perPage=25): Illuminate\Contracts\Pagination\LengthAwarePaginator
@return LengthAwarePaginator<int, User>
resolved @return Illuminate\Contracts\Pagination\LengthAwarePaginator<int, Nvl\Auth\Models\User>
public function profile(Illuminate\Contracts\Auth\Authenticatable $subject): Nvl\Auth\Models\User
public function suggest(Illuminate\Contracts\Auth\Authenticatable $actor, string $search, ?int $limit=null): Illuminate\Database\Eloquent\Collection
@return Collection<int, User>
resolved @return Illuminate\Database\Eloquent\Collection<int, Nvl\Auth\Models\User>
```

## Nvl\Auth\Services\AuthUsers

```text
final readonly class Nvl\Auth\Services\AuthUsers
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\MutationAuthorizer $authorization, Nvl\Auth\Services\UserLocator $users, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes, Nvl\Auth\Contracts\PrincipalSessionContainment $sessions, Nvl\Auth\Services\AuthMemberships $owners, Nvl\Auth\Services\AuthOwnershipState $ownershipState, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Services\ManagementAuthorizer $createAuthorization, Nvl\Auth\Services\AuthModelRegistry $models, Illuminate\Contracts\Container\Container $container, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Auth\Services\ManagementAuthorizer $updateAuthorization, Nvl\Auth\Contracts\PasswordUpdater $passwords, Nvl\Auth\Services\PasswordValidationRules $passwordPolicy, Nvl\Support\Auth\CanonicalActorResolver $canonical, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\RecentAuthenticationProofs $recent, Nvl\Auth\Services\AuthenticationSessions $browserSessions, Nvl\Auth\Services\PrincipalExtensions $extensions, Nvl\Auth\Pipelines\AuthPipeline $pipeline): mixed
public function bulkUpdate(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Enums\UserBulkOperation $operation, array $userIds): array
@param list<string> $userIds
@return array<string, mixed>
public function create(Illuminate\Contracts\Auth\Authenticatable $actor, #[SensitiveParameter()] array $data): Nvl\Auth\Models\User
@param array<string, mixed> $data
public function delete(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\User|string $user): bool
public function deleteOwnAccount(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): bool
@param array<string, mixed> $data
public function restore(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\User|string $user): Nvl\Auth\Models\User
public function setActive(Illuminate\Contracts\Auth\Authenticatable|Nvl\Auth\ValueObjects\SystemMutationContext $authority, Nvl\Auth\Models\User|string $user, #[SensitiveParameter()] array $data): Nvl\Auth\Models\User
@param array<string, mixed> $data
public function update(Illuminate\Contracts\Auth\Authenticatable $actor, Nvl\Auth\Models\User|string $user, #[SensitiveParameter()] array $data): Nvl\Auth\Models\User
@param array<string, mixed> $data
public function updateProfile(Illuminate\Contracts\Auth\Authenticatable $subject, #[SensitiveParameter()] array $data, #[SensitiveParameter()] ?string $grant=null, ?Nvl\Auth\ValueObjects\AuthenticationRequestContext $context=null): Nvl\Auth\Models\User
@param array<string, mixed> $data
```

## Nvl\Auth\Services\Authentication

```text
final readonly class Nvl\Auth\Services\Authentication
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\PrincipalAttributeMapper $principalAttributes, Illuminate\Auth\AuthManager $auth, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Contracts\AuthenticationEligibility $eligibility, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Services\AuthTokens $tokens, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\AuthenticationSessions $sessions, Nvl\Auth\Services\AuthenticationProofs $proofs, Nvl\Auth\Services\PrincipalEmailIdentity $emails, Nvl\Auth\Services\AuthSchemaProbes $probes): mixed
public function completeSecondFactor(#[SensitiveParameter()] array $factorProof, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session): Illuminate\Contracts\Auth\Authenticatable
@param array{code?: mixed, recoveryCode?: mixed} $factorProof
public function hasPendingSecondFactor(Illuminate\Contracts\Session\Session $session): bool
public function login(#[SensitiveParameter()] array $credentials, array $context, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, #[SensitiveParameter()] array $factorProof=[]): Illuminate\Contracts\Auth\Authenticatable
@param array{identifier?: mixed, password?: mixed} $credentials
@param array<string, mixed> $context
@param array{code?: mixed, recoveryCode?: mixed} $factorProof
public function loginWithToken(#[SensitiveParameter()] array $credentials, array $token, array $context=[], #[SensitiveParameter()] array $factorProof=[]): array
@param array{identifier?: mixed, password?: mixed} $credentials
@param array{name: string, abilities: list<string>, expiresAt?: (CarbonImmutable | null)} $token
resolved @param array{name: string, abilities: list<string>, expiresAt?: (Carbon\CarbonImmutable | null)} $token
@param array{ipAddress?: (string | null), userAgent?: (string | null), requestId?: (string | null)} $context
@param array{code?: mixed, recoveryCode?: mixed} $factorProof
@return array{subject: Authenticatable, token: IssuedApiToken}
resolved @return array{subject: Illuminate\Contracts\Auth\Authenticatable, token: Nvl\Auth\Results\IssuedApiToken}
public function proveCredentials(#[SensitiveParameter()] array $credentials, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
@param array{identifier?: mixed, password?: mixed} $credentials
public function proveCredentialsForToken(#[SensitiveParameter()] array $credentials, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
@param array{identifier?: mixed, password?: mixed} $credentials
public function verifyCredentials(#[SensitiveParameter()] array $credentials): Illuminate\Contracts\Auth\Authenticatable
@param array<string, mixed> $credentials
```

## Nvl\Auth\Services\AuthenticationProofs

```text
final readonly class Nvl\Auth\Services\AuthenticationProofs
public function __construct(Nvl\Auth\Services\AuthIdentityChallenges $records, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Contracts\AuthSubjectResolver $subjects, Nvl\Auth\Contracts\AuthenticationEligibility $eligibility, Nvl\Auth\Services\EnrolledFactorAssurancePolicy $enrollment, Nvl\Auth\Contracts\AuthenticationAssurancePolicy $assurance, Nvl\Auth\Services\AuthSecondFactor $secondFactor, Nvl\Support\Auth\CanonicalActorResolver $actors, Nvl\Auth\Services\PrincipalEligibility $nativeEligibility, Nvl\Auth\Contracts\AuthAuditRecorder $audits): mixed
public function available(#[SensitiveParameter()] string $proof): bool
public function completeFactor(#[SensitiveParameter()] string $proof, Nvl\Auth\Enums\AuthenticationDestination $destination, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, #[SensitiveParameter()] array $factorProof): Nvl\Auth\ValueObjects\IssuedAuthenticationProof
@param array{code?: mixed, recoveryCode?: mixed} $factorProof
public function consume(#[SensitiveParameter()] string $proof, Nvl\Auth\Enums\AuthenticationDestination $destination, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context): array
@return array{subject: (Model & Authenticatable), evidence: AuthenticationEvidence}
resolved @return array{subject: (Illuminate\Database\Eloquent\Model & Illuminate\Contracts\Auth\Authenticatable), evidence: Nvl\Auth\ValueObjects\AuthenticationEvidence}
```

## Nvl\Auth\Services\AuthenticationSessions

```text
final readonly class Nvl\Auth\Services\AuthenticationSessions
public function __construct(Nvl\Auth\Services\FeatureGate $features, Nvl\Auth\Services\OwnerAuthenticationSelection $ownerSelection, Nvl\Auth\Pipelines\AuthPipeline $pipeline, Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder $loginMetadata, Nvl\Auth\Contracts\AuthAuditRecorder $audits, Nvl\Auth\Services\AuthOperationBoundary $operations, Nvl\Support\Events\DomainEventDispatcher $domainEvents, Nvl\Auth\Services\AuthenticationProofs $proofs, Illuminate\Auth\AuthManager $auth, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\PrincipalAttributeMapper $principalAttributes, Nvl\Auth\Services\StatefulAuthenticationBoundary $boundary, Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Services\PrincipalSecurity $security, Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\AuthExecutionContext $execution, Nvl\Auth\Services\AuthSchemaProbes $probes): mixed
public function assertCanTransition(?Illuminate\Contracts\Auth\Authenticatable $subject=null): void
public function completeSecondFactor(#[SensitiveParameter()] array $factorProof, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session): Illuminate\Contracts\Auth\Authenticatable
@param array{code?: mixed, recoveryCode?: mixed} $factorProof
public function establishFromProof(#[SensitiveParameter()] string $proof, Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, Nvl\Auth\ValueObjects\AuthenticationRequestContext $context, bool $remember=false): Illuminate\Contracts\Auth\Authenticatable
public function hasPendingSecondFactor(Illuminate\Contracts\Session\Session $session): bool
public function logout(Illuminate\Contracts\Auth\StatefulGuard $guard, Illuminate\Contracts\Session\Session $session, ?string $guardName=null): void
```

## Nvl\Auth\Services\EnrolledFactorAssurancePolicy

```text
final readonly class Nvl\Auth\Services\EnrolledFactorAssurancePolicy implements Nvl\Auth\Contracts\AuthenticationAssurancePolicy
public function __construct(Nvl\Auth\Services\AuthSchemaProbes $probes=new \Nvl\Auth\Services\AuthSchemaProbes()): mixed
public function assertSatisfied(Illuminate\Contracts\Auth\Authenticatable $subject, Nvl\Auth\ValueObjects\AuthenticationEvidence $evidence, Nvl\Auth\Enums\AuthenticationPurpose $purpose): void
public function requiresSecondFactor(Illuminate\Contracts\Auth\Authenticatable $subject): bool
```

## Nvl\Auth\Services\FeatureGate

```text
final readonly class Nvl\Auth\Services\FeatureGate
public function __construct(Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\FeatureManifest $manifest, Nvl\Auth\Services\AuthOwnershipState $ownership, Nvl\Auth\Services\AuthExecutionContext $execution): mixed
public function allows(Nvl\Auth\Enums\AuthFeature $feature, Nvl\Auth\Enums\FeatureOperation $operation): bool
public function assertAllowed(Nvl\Auth\Enums\AuthFeature $feature, Nvl\Auth\Enums\FeatureOperation $operation): void
```

## Nvl\Auth\Services\OwnerAuthenticationIntents

```text
final readonly class Nvl\Auth\Services\OwnerAuthenticationIntents
public function __construct(Nvl\Auth\Services\SecretHasher $hasher, Nvl\Auth\Services\OpaqueTokenFactory $tokens, Nvl\Ownership\Services\OwnerIdentityResolver $owners, Nvl\Ownership\Contracts\OwnerAvailability $availability, Nvl\Ownership\Services\OwnershipInstallationState $installation, Nvl\Support\Ownership\Contracts\OwnershipReadiness $readiness, Nvl\Auth\Services\AuthConfiguration $configuration): mixed
public function consume(string $nonce, Nvl\Auth\Enums\OwnerAuthenticationPurpose $purpose, string $sessionBinding, Nvl\Support\Ownership\ValueObjects\OwnerReference $expectedOwner, ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, ?string $provider=null): Nvl\Support\Ownership\ValueObjects\OwnerReference
public function issue(Nvl\Support\Ownership\ValueObjects\OwnerReference $owner, Nvl\Auth\Enums\OwnerAuthenticationPurpose $purpose, string $sessionBinding, ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, ?string $provider=null, ?string $returnPath=null): array
@return array{id: string, nonce: string, expiresAt: CarbonImmutable}
resolved @return array{id: string, nonce: string, expiresAt: Carbon\CarbonImmutable}
```

## Nvl\Auth\Services\PrincipalEmailIdentity

```text
final readonly class Nvl\Auth\Services\PrincipalEmailIdentity
public const mixed INDEX="nvl_auth_users_email_identity_hash_unique"
public function __construct(Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes): mixed
public static function key(string $email): string
public static function normalize(string $email): string
```

## Nvl\Auth\Services\PrincipalEmailIdentityAdoption

```text
final readonly class Nvl\Auth\Services\PrincipalEmailIdentityAdoption
public function __construct(Nvl\Auth\Services\AuthModelRegistry $models, Nvl\Auth\Contracts\PrincipalAttributeMapper $attributes, Nvl\Auth\Services\MutationAuthorizer $authorization, Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Contracts\AuthAuditRecorder $audits): mixed
public function apply(Nvl\Auth\ValueObjects\SystemMutationContext $authority): array
@return array{updated: int, finalized: bool}
public function plan(): array
@return array{missing: int, collisions: list<array{key: string, subjectIds: list<string>}>, ready: bool}
```

## Nvl\Auth\Services\SocialProviderRegistry

```text
final readonly class Nvl\Auth\Services\SocialProviderRegistry
public function __construct(Nvl\Auth\Services\AuthConfiguration $configuration, Nvl\Auth\Services\SocialProviderConfiguration $providers, Nvl\Auth\Contracts\SocialIdentityProviderFactory $factory): mixed
public function assertAvailable(string $provider): void
public function providers(): array
@return array<string, array{enabled: bool, label: string, supportsReauthentication: bool}>
```

## Nvl\Auth\Services\UsableAccountAuthenticationPolicy

```text
final readonly class Nvl\Auth\Services\UsableAccountAuthenticationPolicy implements Nvl\Auth\Contracts\AccountAuthenticationPolicy
public function __construct(Nvl\Auth\Services\AuthAccountSecurity $inventory, Nvl\Auth\Services\PrincipalSecurity $security): mixed
public function assertRemovalAllowed(Illuminate\Contracts\Auth\Authenticatable $subject, string $kind, string $credentialId): void
```

## Nvl\Auth\ValueObjects\AuthDeliveryRequest

```text
final readonly class Nvl\Auth\ValueObjects\AuthDeliveryRequest
public function __construct(string $messageId, Nvl\Auth\Enums\AuthFeature $feature, Nvl\Auth\Enums\AuthMessageType $type, string $recipient, #[SensitiveParameter()] array $payload, Carbon\CarbonImmutable $expiresAt, ?string $locale=null, array $metadata=[], ?Nvl\Auth\ValueObjects\SubjectReference $subject=null, ?array $invitation=null): mixed
@param array<string, mixed> $payload
@param array<string, mixed> $metadata
@param (array<string, mixed> | null) $invitation
public function __debugInfo(): array
@return array<string, mixed>
public readonly Carbon\CarbonImmutable $expiresAt
public readonly Nvl\Auth\Enums\AuthFeature $feature
public readonly ?array $invitation
@param (array<string, mixed> | null) $invitation
public readonly ?string $locale
public readonly string $messageId
public readonly array $metadata
@param array<string, mixed> $metadata
#[SensitiveParameter()]
public readonly array $payload
@param array<string, mixed> $payload
public readonly string $recipient
public readonly ?Nvl\Auth\ValueObjects\SubjectReference $subject
public readonly Nvl\Auth\Enums\AuthMessageType $type
```

## Nvl\Auth\ValueObjects\AuthEventContext

```text
final readonly class Nvl\Auth\ValueObjects\AuthEventContext
public function __construct(Nvl\Support\Ownership\Enums\OwnershipContextMode $mode, ?Nvl\Support\Ownership\ValueObjects\OwnerReference $owner=null): mixed
public static function capture(Nvl\Support\Ownership\Contracts\OwnershipContext $context): self
public static function centralIdentity(): self
public readonly Nvl\Support\Ownership\Enums\OwnershipContextMode $mode
public readonly ?Nvl\Support\Ownership\ValueObjects\OwnerReference $owner
```

## Nvl\Auth\ValueObjects\AuthPipelineContext

```text
final readonly class Nvl\Auth\ValueObjects\AuthPipelineContext
public function __construct(string $name, array $attributes=[], ?Nvl\Auth\ValueObjects\SubjectReference $subject=null): mixed
@param array<string, mixed> $attributes
public readonly array $attributes
@param array<string, mixed> $attributes
public readonly string $name
public readonly ?Nvl\Auth\ValueObjects\SubjectReference $subject
```

## Nvl\Auth\ValueObjects\AuthenticationEvidence

```text
final readonly class Nvl\Auth\ValueObjects\AuthenticationEvidence
public function satisfiesMfa(): bool
public readonly Nvl\Auth\ValueObjects\AuthenticationRequestContext $context
public readonly Nvl\Auth\Enums\AuthenticationDestination $destination
public readonly Carbon\CarbonImmutable $expiresAt
public readonly array $factors
@param list<string> $factors
public readonly Nvl\Auth\Enums\AuthenticationMethod $method
public readonly ?string $provider
public readonly int $revision
public readonly Nvl\Auth\ValueObjects\SubjectReference $subject
public readonly Carbon\CarbonImmutable $verifiedAt
```

## Nvl\Auth\ValueObjects\AuthenticationRequestContext

```text
final readonly class Nvl\Auth\ValueObjects\AuthenticationRequestContext implements JsonSerializable
public function __construct(?string $ipAddress=null, ?string $userAgent=null, ?string $requestId=null, ?string $ownerIntentNonce=null, ?string $ownerSessionBinding=null, ?Nvl\Support\Ownership\ValueObjects\OwnerReference $requestedOwner=null, ?Nvl\Auth\Enums\OwnerAuthenticationPurpose $ownerPurpose=null, bool $ownerIntentSubjectBound=false, ?string $ownerProvider=null, ?string $guardName=null, ?string $sessionBinding=null, ?string $tokenNamespace=null, ?string $flowNonce=null, ?string $browserSessionId=null, #[SensitiveParameter()] ?string $browserBinding=null): mixed
public function __debugInfo(): array
@return array<string, mixed>
public function assertBound(Nvl\Auth\Enums\AuthenticationDestination $destination): void
public function facts(): array
@return array<string, mixed>
public static function fromFacts(array $facts): self
@param array<array-key, mixed> $facts
public function jsonSerialize(): array
@return array<string, mixed>
#[SensitiveParameter()]
public readonly ?string $browserBinding
public readonly ?string $browserSessionId
public readonly ?string $flowNonce
public readonly ?string $guardName
public readonly ?string $ipAddress
public readonly ?string $ownerIntentNonce
public readonly bool $ownerIntentSubjectBound
public readonly ?string $ownerProvider
public readonly ?Nvl\Auth\Enums\OwnerAuthenticationPurpose $ownerPurpose
public readonly ?string $ownerSessionBinding
public readonly ?string $requestId
public readonly ?Nvl\Support\Ownership\ValueObjects\OwnerReference $requestedOwner
public readonly ?string $sessionBinding
public readonly ?string $tokenNamespace
public readonly ?string $userAgent
```

## Nvl\Auth\ValueObjects\ExternalIdentity

```text
final readonly class Nvl\Auth\ValueObjects\ExternalIdentity
public function __construct(string $provider, string $providerUserId, ?string $email=null, ?string $name=null, ?string $avatar=null, array $profile=[], bool $emailVerified=false, ?string $emailVerificationSource=null, ?string $issuer=null): mixed
@param array<string, mixed> $profile
public readonly ?string $avatar
public readonly ?string $email
public readonly ?string $emailVerificationSource
public readonly bool $emailVerified
public readonly ?string $issuer
public readonly ?string $name
public readonly array $profile
@param array<string, mixed> $profile
public readonly string $provider
public readonly string $providerUserId
```

## Nvl\Auth\ValueObjects\InvitationIssuanceContext

```text
final readonly class Nvl\Auth\ValueObjects\InvitationIssuanceContext
public function __construct(?Carbon\CarbonImmutable $expiresAt=null, ?string $returnPath=null): mixed
public readonly ?Carbon\CarbonImmutable $expiresAt
public readonly ?string $returnPath
```

## Nvl\Auth\ValueObjects\IssuedAuthenticationProof

```text
final readonly class Nvl\Auth\ValueObjects\IssuedAuthenticationProof implements JsonSerializable
public function __construct(#[SensitiveParameter()] string $proof): mixed
public function __debugInfo(): array
@return array{proof: string}
public function __serialize(): never
public function jsonSerialize(): never
public function reveal(): string
```

## Nvl\Auth\ValueObjects\IssuedRecentAuthentication

```text
final readonly class Nvl\Auth\ValueObjects\IssuedRecentAuthentication implements JsonSerializable
public function __construct(#[SensitiveParameter()] string $proof): mixed
public function __debugInfo(): array
@return array{proof: string}
public function __serialize(): never
public function jsonSerialize(): never
public function reveal(): string
```

## Nvl\Auth\ValueObjects\IssuedSocialIntent

```text
final readonly class Nvl\Auth\ValueObjects\IssuedSocialIntent implements JsonSerializable
public function __construct(#[SensitiveParameter()] string $proof, Carbon\CarbonImmutable $expiresAt): mixed
public function __debugInfo(): array
@return array{proof: string}
public function __serialize(): never
public function jsonSerialize(): never
public function reveal(): string
public readonly Carbon\CarbonImmutable $expiresAt
```

## Nvl\Auth\ValueObjects\IssuedSocialRegistration

```text
final readonly class Nvl\Auth\ValueObjects\IssuedSocialRegistration implements JsonSerializable
public function __construct(#[SensitiveParameter()] string $proof, Carbon\CarbonImmutable $expiresAt): mixed
public function __debugInfo(): array
@return array{proof: string}
public function __serialize(): never
public function jsonSerialize(): never
public function reveal(): string
public readonly Carbon\CarbonImmutable $expiresAt
```

## Nvl\Auth\ValueObjects\PasskeyAssertion

```text
final readonly class Nvl\Auth\ValueObjects\PasskeyAssertion
public function __construct(string $credentialId, int $signatureCounter, bool $backupEligible, bool $backedUp, bool $userVerified): mixed
public readonly bool $backedUp
public readonly bool $backupEligible
public readonly string $credentialId
public readonly int $signatureCounter
public readonly bool $userVerified
```

## Nvl\Auth\ValueObjects\PasskeyCeremonyOptions

```text
final readonly class Nvl\Auth\ValueObjects\PasskeyCeremonyOptions
public function __construct(string $ceremonyId, array $options, array $state, Carbon\CarbonImmutable $expiresAt): mixed
@param array<string, mixed> $options
@param array<string, mixed> $state
public readonly string $ceremonyId
public readonly Carbon\CarbonImmutable $expiresAt
public readonly array $options
@param array<string, mixed> $options
public readonly array $state
@param array<string, mixed> $state
```

## Nvl\Auth\ValueObjects\PasskeyCredential

```text
final readonly class Nvl\Auth\ValueObjects\PasskeyCredential
public function __construct(string $credentialId, string $publicKey, string $userHandle, int $signatureCounter, bool $backupEligible, bool $backedUp): mixed
public readonly bool $backedUp
public readonly bool $backupEligible
public readonly string $credentialId
public readonly string $publicKey
public readonly int $signatureCounter
public readonly string $userHandle
```

## Nvl\Auth\ValueObjects\PasskeyRegistration

```text
final readonly class Nvl\Auth\ValueObjects\PasskeyRegistration
public function __construct(string $credentialId, string $publicKey, string $userHandle, int $signatureCounter, array $transports=[], bool $backupEligible=false, bool $backedUp=false): mixed
@param list<string> $transports
public readonly bool $backedUp
public readonly bool $backupEligible
public readonly string $credentialId
public readonly string $publicKey
public readonly int $signatureCounter
public readonly array $transports
@param list<string> $transports
public readonly string $userHandle
```

## Nvl\Auth\ValueObjects\RoleTemplate

```text
final readonly class Nvl\Auth\ValueObjects\RoleTemplate
public function __construct(string $key, array $permissions, ?string $roleName=null, ?string $displayName=null, ?string $description=null, bool $system=true, ?string $parentRole=null, int $priority=0, array $metadata=[]): mixed
@param list<string> $permissions
@param array<string, mixed> $metadata
public function toArray(): array
@return array<string, mixed>
public function toMutation(?string $targetRoleName=null, ?string $parentId=null): array
@return array{name: string, displayName: (string | null), description: (string | null), parentId: (string | null), priority: int, system: bool, permissions: list<string>, metadata: array<string, mixed>}
public readonly ?string $description
public readonly ?string $displayName
public readonly string $key
public readonly array $metadata
@param array<string, mixed> $metadata
public readonly ?string $parentRole
public readonly array $permissions
@param list<string> $permissions
public readonly int $priority
public readonly ?string $roleName
public readonly bool $system
```

## Nvl\Auth\ValueObjects\SubjectReference

```text
final readonly class Nvl\Auth\ValueObjects\SubjectReference
public function __construct(string $type, string $identifier): mixed
public static function fromAuthenticatable(Illuminate\Contracts\Auth\Authenticatable $subject): self
public readonly string $identifier
public readonly string $type
```

## Nvl\Auth\ValueObjects\SystemMutationContext

```text
final readonly class Nvl\Auth\ValueObjects\SystemMutationContext
public function __construct(string $reason, string $correlationId, ?Illuminate\Contracts\Auth\Authenticatable $actor=null, array $metadata=[]): mixed
@param array<string, mixed> $metadata
public function auditMetadata(): array
@return array{system: array{reason: string, correlation_id: string, metadata: array<string, mixed>}}
public readonly ?Illuminate\Contracts\Auth\Authenticatable $actor
public readonly string $correlationId
public readonly array $metadata
@param array<string, mixed> $metadata
public readonly string $reason
```
