<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;
use SensitiveParameter;
use Throwable;

/**
 * Completes native password authentication while consumers retain transport control.
 *
 * @api
 */
final readonly class Authentication
{
    use IssuesAuthenticationProofs;

    private const string PendingFactorLogin = 'nvl-auth.credential_login';

    public function __construct(private FeatureGate $features, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private AuthManager $auth, private AuthAuditRecorder $audits, private AuthenticationEligibility $eligibility, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents, private AuthTokens $tokens, private SecretHasher $hasher, private AuthIdentityChallenges $records, private PrincipalSecurity $security, private AuthenticationSessions $sessions, private AuthenticationProofs $proofs) {}

    /** Verify native password credentials into a browser-bound bearer capability.
     * @param  array{identifier?: mixed, password?: mixed}  $credentials
     */
    public function proveCredentials(#[SensitiveParameter] array $credentials, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        return $this->passwordProof($credentials, $context, AuthenticationDestination::Session);
    }

    /** Verify native password credentials for one trusted stateless client flow.
     * @param  array{identifier?: mixed, password?: mixed}  $credentials
     */
    public function proveCredentialsForToken(#[SensitiveParameter] array $credentials, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Issue);

        return $this->passwordProof($credentials, $context, AuthenticationDestination::ApiToken);
    }

    /** @param array{identifier?: mixed, password?: mixed} $credentials
     * @param  array<string, mixed>  $context  Trusted host metadata and owner intent, never credential fields.
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof
     */
    public function login(#[SensitiveParameter] array $credentials, array $context, StatefulGuard $guard, Session $session, #[SensitiveParameter] array $factorProof = []): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->sessions->assertCanTransition();
        $remember = $context['remember'] ?? false;
        if (! is_bool($remember) || array_intersect(array_keys($context), ['guardName', 'sessionBinding', 'tokenNamespace', 'flowNonce']) !== []) {
            throw new \InvalidArgumentException('Invalid or protected authentication context.');
        }
        unset($context['remember']);
        $name = $this->configuration->string('guard', 'web');
        if ($this->auth->guard($name) !== $guard) {
            throw new AuthException('authentication_binding_invalid', 'The authentication guard does not match.', 422);
        }
        $requestContext = AuthenticationRequestContext::fromFacts([...$context, 'guardName' => $name, 'sessionBinding' => $session->getId()]);
        $session->forget(self::PendingFactorLogin);
        $proof = $this->proveCredentials($credentials, $requestContext);
        $this->completePasswordFactor($proof, $credentials, AuthenticationDestination::Session, $requestContext, $factorProof);

        return $this->sessions->establishFromProof($proof->reveal(), $guard, $session, $requestContext, $remember);
    }

    public function hasPendingSecondFactor(Session $session): bool
    {
        return $this->sessions->hasPendingSecondFactor($session);
    }

    /** @param array{code?: mixed, recoveryCode?: mixed} $factorProof */
    public function completeSecondFactor(#[SensitiveParameter] array $factorProof, StatefulGuard $guard, Session $session): Authenticatable
    {
        return $this->sessions->completeSecondFactor($factorProof, $guard, $session);
    }

    /** @param array{identifier?: mixed, password?: mixed} $credentials
     * @param  array{name: string, abilities: list<string>, expiresAt?: CarbonImmutable|null}  $token
     * @param  array{ipAddress?: string|null, userAgent?: string|null, requestId?: string|null}  $context
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof
     * @return array{subject: Authenticatable, token: IssuedApiToken}
     */
    public function loginWithToken(#[SensitiveParameter] array $credentials, array $token, array $context = [], #[SensitiveParameter] array $factorProof = []): array
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Issue);
        if (array_diff(array_keys($context), ['ipAddress', 'userAgent', 'requestId']) !== []) {
            throw new \InvalidArgumentException('Unknown stateless authentication context.');
        }
        $requestContext = new AuthenticationRequestContext(...[...$context, 'tokenNamespace' => 'native-password', 'flowNonce' => bin2hex(random_bytes(32))]);
        $proof = $this->proveCredentialsForToken($credentials, $requestContext);
        $this->completePasswordFactor($proof, $credentials, AuthenticationDestination::ApiToken, $requestContext, $factorProof);

        return $this->tokens->authenticateFromProof($proof->reveal(), $token, $requestContext);
    }

    /** Verify credentials without creating a session.
     * @param  array<string, mixed>  $credentials
     */
    public function verifyCredentials(
        #[SensitiveParameter]
        array $credentials
    ): Authenticatable {
        return $this->verifiedCredentials($credentials)['subject'];
    }

    /**
     * Verify this canonical subject's password for native recent authentication.
     *
     * @internal
     */
    public function proveReauthentication(Authenticatable $subject, #[SensitiveParameter] string $password, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        if (! $subject instanceof Model) {
            throw AuthException::invalidConfiguration('Reauthentication requires an Eloquent principal.');
        }
        $column = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));

        return $this->passwordProof(['identifier' => $subject->getAttribute($column), 'password' => $password], $context, AuthenticationDestination::Reauthentication, SubjectReference::fromAuthenticatable($subject));
    }

    /** @param array{identifier?: mixed, password?: mixed} $credentials */
    private function passwordProof(#[SensitiveParameter] array $credentials, AuthenticationRequestContext $context, AuthenticationDestination $destination, ?SubjectReference $expectedSubject = null): IssuedAuthenticationProof
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $context->assertBound($destination);
        $this->operations->central(AuthIdentityOperation::Login);
        $identifier = is_string($credentials['identifier'] ?? null) ? $credentials['identifier'] : '';
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $this->domainEvents->dispatch(new AuthenticationAttempted($identifierName, $identifier), (new AuthAudit)->getConnection());
        try {
            $verified = $this->verifiedCredentials($credentials);
            $subject = $verified['subject'];
            if ($expectedSubject !== null && SubjectReference::fromAuthenticatable($subject) != $expectedSubject) {
                throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
            }
            $this->operations->central(AuthIdentityOperation::Login, $subject);
            $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);

            return $this->issueNativeProof($subject, AuthenticationMethod::Password, $destination, $context, $verified['revision'], passwordHash: $verified['passwordHash']);
        } catch (Throwable $exception) {
            $this->rejectPasswordAttempt($credentials, $exception);
            throw $exception;
        }
    }

    /** @param array{identifier?: mixed, password?: mixed} $credentials
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof
     */
    private function completePasswordFactor(IssuedAuthenticationProof $proof, #[SensitiveParameter] array $credentials, AuthenticationDestination $destination, AuthenticationRequestContext $context, #[SensitiveParameter] array $factorProof): void
    {
        if ($factorProof === []) {
            return;
        }
        try {
            $this->proofs->completeFactor($proof->reveal(), $destination, $context, $factorProof);
        } catch (Throwable $exception) {
            $this->rejectPasswordAttempt($credentials, $exception);
            throw $exception;
        }
    }

    /** @param array{identifier?: mixed, password?: mixed} $credentials */
    private function rejectPasswordAttempt(#[SensitiveParameter] array $credentials, Throwable $exception): void
    {
        $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
        $identifier = is_string($credentials['identifier'] ?? null) ? $credentials['identifier'] : '';
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $this->audits->record('authentication.failed', outcome: 'failure', metadata: ['reason' => $reason]);
        $this->domainEvents->dispatch(new AuthenticationRejected($identifierName, $identifier, $reason), (new AuthAudit)->getConnection());
    }

    /** Capture verification freshness before invoking the credential provider.
     * @param  array<string, mixed>  $credentials
     * @return array{subject: Model&Authenticatable, passwordHash: string, revision: int}
     */
    private function verifiedCredentials(#[SensitiveParameter] array $credentials): array
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        if (array_diff(array_keys($credentials), ['identifier', 'password']) !== [] || ! is_string($credentials['identifier'] ?? null) || trim($credentials['identifier']) === '' || strlen($credentials['identifier']) > 255 || ! is_string($credentials['password'] ?? null) || $credentials['password'] === '' || strlen($credentials['password']) > 4096) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $identifier = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $provider = $this->auth->createUserProvider($this->configuration->string('provider', 'users'));
        if ($provider === null) {
            throw AuthException::invalidConfiguration('A credential provider is required.');
        }
        $native = [$identifier => $credentials['identifier'], 'password' => $credentials['password']];
        $subject = $provider->retrieveByCredentials($native);
        if (! $subject instanceof Model) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $passwordHash = $subject->getAuthPassword();
        $revision = $this->security->revisionSnapshot($subject);
        if (! $provider->validateCredentials($subject, $native)) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }

        return $subject->getConnection()->transaction(function () use ($subject, $passwordHash, $revision, $provider, $native): array {
            $state = $this->security->lock($subject);
            $canonical = $subject->newQuery()->useWritePdo()->whereKey($subject->getKey())->first();
            if (! $canonical instanceof Authenticatable || $state->revision !== $revision || ! hash_equals($passwordHash, $canonical->getAuthPassword())) {
                throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
            }
            $provider->rehashPasswordIfRequired($canonical, $native);

            return ['subject' => $canonical, 'passwordHash' => $canonical->getAuthPassword(), 'revision' => $revision];
        });
    }
}
