<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\User;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use SensitiveParameter;
use Throwable;

/**
 * Completes credential authentication for browser sessions and stateless API tokens.
 *
 * @api
 */
final readonly class Authentication
{
    private const string PendingFactorLogin = 'nvl-auth.credential_login';

    private const int FactorLifetimeSeconds = 300;

    private const int FactorMaximumAttempts = 5;

    /**
     * Create the native credential authentication operations.
     */
    public function __construct(private FeatureGate $features, private OwnerAuthenticationSelection $ownerSelection, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private AuthManager $auth, private AuthPipeline $pipeline, private AuthAuditRecorder $audits, private AuthenticationEligibility $eligibility, private SuccessfulLoginMetadataRecorder $loginMetadata, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents, private AuthModelRegistry $models, private AuthSecondFactor $secondFactor, private AuthTokens $tokens, private AuthCommittedAudit $committedAudits, private ConnectionCommitCallbacks $commits, private SecretHasher $hasher, private AuthIdentityChallenges $challenges, private PrincipalSecurity $security) {}

    /**
     * Complete password and enrolled factor proof before issuing a stateless token.
     *
     * Native token, principal metadata and native audit writes share one connection and
     * transaction. Host audit adapters and domain events follow the outer source commit.
     * Factor proof consumption precedes the login pipeline and retains its replay protection
     * when that pipeline rejects. No guard, session or owner-session selection is accessed.
     *
     * @param  array{identifier?: mixed, password?: mixed}  $credentials  Both strings are required and validated natively.
     * @param  array{name: string, abilities: list<string>, expiresAt?: CarbonImmutable|null}  $token
     * @param  array{ipAddress?: string|null, userAgent?: string|null, requestId?: string|null}  $context
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof  At most one non-empty string proof; required for an enrolled principal while TOTP is enabled.
     * @return array{subject: Authenticatable, token: IssuedApiToken}
     */
    public function loginWithToken(
        #[SensitiveParameter] array $credentials,
        array $token,
        array $context = [],
        #[SensitiveParameter] array $factorProof = [],
    ): array {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Issue);
        $this->operations->central(AuthIdentityOperation::Login);
        if (array_diff(array_keys($context), ['ipAddress', 'userAgent', 'requestId']) !== []
            || array_diff(array_keys($factorProof), ['code', 'recoveryCode']) !== []
            || count($factorProof) > 1) {
            throw new \InvalidArgumentException('Unknown or conflicting stateless authentication input.');
        }
        foreach ($factorProof as $proof) {
            if (! is_string($proof) || trim($proof) === '' || strlen($proof) > 128) {
                throw new \InvalidArgumentException('Factor proof must be a bounded non-empty string.');
            }
        }
        $requestContext = new AuthenticationRequestContext(...$context);
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $identifier = is_string($credentials['identifier'] ?? null) ? $credentials['identifier'] : '';
        $connection = (new AuthAudit)->getConnection();
        $reference = null;
        $subject = null;
        $sourceCommitted = false;
        $this->domainEvents->dispatch(new AuthenticationAttempted($identifierName, $identifier), $connection);

        try {
            $subject = $this->verifyCredentials($credentials);
            $passwordHash = $subject->getAuthPassword();
            $reference = SubjectReference::fromAuthenticatable($subject);
            $subject = $this->freshPrincipal($reference);
            $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
            $factorVerified = $this->verifyLoginFactor($subject, $factorProof);
            $connection = $subject->getConnection();
            if ($this->tokens->connection($subject) !== $connection || (new AuthAudit)->getConnection() !== $connection) {
                throw AuthException::invalidConfiguration('Stateless authentication requires principal, token and audit writes on one connection.');
            }

            return $connection->transaction(function () use ($reference, $identifierName, $requestContext, $token, $connection, $passwordHash, $factorVerified, &$sourceCommitted): array {
                $this->commits->afterCommit($connection, static function () use (&$sourceCommitted): void {
                    $sourceCommitted = true;
                });
                $principal = $this->eligibleCredentialPrincipal($reference, $passwordHash, $factorVerified, lock: true);
                $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', ['identifier_name' => $identifierName, 'method' => AuthenticationPurpose::CredentialLogin->value, 'stateless' => true], $reference), fn (): Authenticatable => $principal);
                if (SubjectReference::fromAuthenticatable($authenticated) != $reference) {
                    throw new AuthException('login_rejected', 'The login pipeline changed the authenticated principal.', 422);
                }
                $principal = $this->eligibleCredentialPrincipal($reference, $passwordHash, $factorVerified);
                $issued = $this->tokens->create($principal, $token);
                $principal = $this->eligibleCredentialPrincipal($reference, $passwordHash, $factorVerified);
                $this->loginMetadata->record($principal, $requestContext);
                $this->committedAudits->withRecorder($this->audits)->record($connection, 'authentication.succeeded', subject: $reference, actor: $principal, metadata: ['method' => AuthenticationPurpose::CredentialLogin->value, 'stateless' => true]);
                $this->domainEvents->dispatch(new UserAuthenticated($reference), $connection);

                return ['subject' => $principal, 'token' => $issued];
            });
        } catch (Throwable $exception) {
            if ($sourceCommitted) {
                throw $exception;
            }
            $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
            $this->audits->record($reference === null ? 'authentication.failed' : 'authentication.rejected', outcome: 'failure', subject: $reference, actor: $subject, metadata: ['method' => AuthenticationPurpose::CredentialLogin->value, 'stateless' => true, 'reason' => $reason]);
            $this->domainEvents->dispatch(new AuthenticationRejected($identifierName, $identifier, $reason, $reference), $connection);
            throw $exception;
        }
    }

    /**
     * Complete credential/factor proof and establish the supplied browser session.
     *
     * When enrolled proof is missing, stores a five-minute, password-bound continuation
     * only in the supplied trusted server session and throws second_factor_required.
     * No guard authentication, success metadata or success fact precedes factor proof.
     *
     * @param  array<string, mixed>  $credentials
     * @param  array{remember?: mixed, ipAddress?: string|null, userAgent?: string|null, requestId?: string|null, ownerIntentNonce?: string|null, ownerSessionBinding?: string|null, requestedOwner?: OwnerReference|null, ownerPurpose?: OwnerAuthenticationPurpose|null, ownerIntentSubjectBound?: bool, ownerProvider?: string|null}  $context
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof
     */
    public function login(
        #[SensitiveParameter] array $credentials,
        array $context,
        StatefulGuard $guard,
        Session $session,
        #[SensitiveParameter] array $factorProof = [],
    ): Authenticatable {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::Login);
        $remember = $context['remember'] ?? false;
        if (! is_bool($remember)) {
            throw new \InvalidArgumentException('Remember must be boolean.');
        }
        unset($context['remember']);
        $requestContext = new AuthenticationRequestContext(...$context);
        $session->forget(self::PendingFactorLogin);
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $identifier = is_string($credentials['identifier'] ?? null) ? $credentials['identifier'] : '';
        $this->domainEvents->dispatch(new AuthenticationAttempted($identifierName, $identifier), (new AuthAudit)->getConnection());
        $subject = null;
        $reference = null;
        try {
            $subject = $this->verifyCredentials($credentials);
            $passwordHash = $subject->getAuthPassword();
            $reference = SubjectReference::fromAuthenticatable($subject);
            $subject = $this->freshPrincipal($reference);
            $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
            if ($factorProof === [] && $this->requiresSecondFactor($subject)) {
                $secret = bin2hex(random_bytes(32));
                $challenge = (new Challenge)->getConnection()->transaction(fn (): Challenge => $this->challenges->create([
                    'type' => 'credential_second_factor',
                    'purpose' => AuthenticationPurpose::CredentialLogin->value,
                    'subject_type' => $reference->type,
                    'subject_id' => $reference->identifier,
                    'secret_hash' => $this->hasher->hash('credential-login-continuation', $secret),
                    'payload' => [
                        'passwordBinding' => $this->hasher->hash('credential-login-password', $passwordHash),
                        'remember' => $remember,
                    ],
                    'expires_at' => CarbonImmutable::now()->addSeconds(self::FactorLifetimeSeconds),
                    'max_attempts' => self::FactorMaximumAttempts,
                ]));
                $session->put(self::PendingFactorLogin, [
                    'challengeId' => $challenge->identifier(),
                    'secret' => $secret,
                    'requestContext' => $requestContext,
                ]);
                $guard->logout();
                $this->audits->record('authentication.factor_required', subject: $reference, actor: $subject);
                throw new AuthException('second_factor_required', 'An enrolled second factor is required.', 422);
            }
            $factorVerified = $this->verifyLoginFactor($subject, $factorProof);

            return $this->finishStatefulLogin($reference, $passwordHash, $factorVerified, $requestContext, $remember, $guard, $session);
        } catch (Throwable $exception) {
            if ($exception instanceof AuthException && $exception->errorCode === 'second_factor_required') {
                throw $exception;
            }
            $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
            $this->audits->record($reference === null ? 'authentication.failed' : 'authentication.rejected', outcome: 'failure', subject: $reference, actor: $subject, metadata: ['reason' => $reason]);
            $this->domainEvents->dispatch(new AuthenticationRejected($identifierName, $identifier, $reason, $reference), (new AuthAudit)->getConnection());
            throw $exception;
        }
    }

    /** Inspect only the bounded continuation retained by the native credential operation. */
    public function hasPendingSecondFactor(Session $session): bool
    {
        return $this->pendingChallenge($session)?->isUsable() === true;
    }

    /**
     * Finish a native primary-proof continuation using TOTP or a one-use recovery code.
     *
     * The supplied session is the authority; transport cannot select a principal or
     * provide a fabricated primary-proof marker. Invalid proof spends one of five
     * attempts. Successful proof consumes the continuation before the login pipeline.
     *
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof
     */
    public function completeSecondFactor(#[SensitiveParameter] array $factorProof, StatefulGuard $guard, Session $session): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $pending = $session->get(self::PendingFactorLogin);
        if (! is_array($pending) || ! ($pending['requestContext'] ?? null) instanceof AuthenticationRequestContext) {
            $session->forget(self::PendingFactorLogin);
            throw new AuthException('login_challenge_invalid', 'The credential login continuation is unavailable.', 422);
        }
        $snapshot = $this->pendingChallenge($session);
        if ($snapshot === null || ! $snapshot->isUsable() || ! is_string($snapshot->subject_type) || ! is_string($snapshot->subject_id)) {
            throw new AuthException('login_challenge_invalid', 'The credential login continuation is unavailable.', 422);
        }
        $candidate = $this->freshPrincipal(new SubjectReference($snapshot->subject_type, $snapshot->subject_id));
        $result = (new Challenge)->getConnection()->transaction(function () use ($session, $factorProof, $snapshot, $candidate): array|Throwable {
            $this->security->lock($candidate);
            $this->security->lockChallenges($candidate);
            $challenge = $this->pendingChallenge($session, lock: true);
            if ($challenge === null || ! $challenge->isUsable() || $challenge->identifier() !== $snapshot->identifier()
                || $challenge->subject_type !== $snapshot->subject_type || $challenge->subject_id !== $snapshot->subject_id) {
                return new AuthException('login_challenge_invalid', 'The credential login continuation is unavailable.', 422);
            }
            $payload = $challenge->payload;
            if (! is_array($payload) || ! is_string($payload['passwordBinding'] ?? null) || ! is_bool($payload['remember'] ?? null)) {
                $challenge->revoked_at = CarbonImmutable::now();
                $this->challenges->save($challenge);

                return new AuthException('login_challenge_invalid', 'The credential login continuation is unavailable.', 422);
            }
            $challenge->attempts++;
            $this->challenges->save($challenge);
            try {
                $reference = new SubjectReference($challenge->subject_type, $challenge->subject_id);
                $subject = $this->freshPrincipal($reference);
                $passwordHash = $subject->getAuthPassword();
                if (! hash_equals($payload['passwordBinding'], $this->hasher->hash('credential-login-password', $passwordHash))) {
                    $challenge->revoked_at = CarbonImmutable::now();
                    $this->challenges->save($challenge);
                    throw new AuthException('login_challenge_invalid', 'The credential login continuation is unavailable.', 422);
                }
                $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
                $factorVerified = $this->verifyLoginFactor($subject, $factorProof);
                $challenge->consumed_at = CarbonImmutable::now();
                $this->challenges->save($challenge);

                return ['reference' => $reference, 'passwordHash' => $passwordHash, 'factorVerified' => $factorVerified, 'remember' => $payload['remember']];
            } catch (Throwable $exception) {
                return $exception;
            }
        });
        if ($result instanceof Throwable) {
            if (! $this->hasPendingSecondFactor($session)) {
                $session->forget(self::PendingFactorLogin);
            }
            throw $result;
        }
        $session->forget(self::PendingFactorLogin);

        return $this->finishStatefulLogin($result['reference'], $result['passwordHash'], $result['factorVerified'], $pending['requestContext'], $result['remember'], $guard, $session);
    }

    /** Verify credentials without creating a session.
     * @param  array<string, mixed>  $credentials
     */
    public function verifyCredentials(
        #[SensitiveParameter]
        array $credentials
    ): Authenticatable {
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
        if ($subject === null || ! $provider->validateCredentials($subject, $native)) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $provider->rehashPasswordIfRequired($subject, $native);

        return $subject;
    }

    /** Resolve only the native, session-held opaque primary-proof credential.
     *
     * @internal
     */
    private function pendingChallenge(Session $session, bool $lock = false): ?Challenge
    {
        $pending = $session->get(self::PendingFactorLogin);
        if (! is_array($pending) || ! is_string($pending['challengeId'] ?? null) || ! Str::isUuid($pending['challengeId'])
            || ! is_string($pending['secret'] ?? null) || preg_match('/\A[0-9a-f]{64}\z/', $pending['secret']) !== 1
            || ! ($pending['requestContext'] ?? null) instanceof AuthenticationRequestContext) {
            return null;
        }
        $query = $this->challenges->query()->whereKey($pending['challengeId'])->where('type', 'credential_second_factor')
            ->where('purpose', AuthenticationPurpose::CredentialLogin->value)
            ->where('secret_hash', $this->hasher->hash('credential-login-continuation', $pending['secret']));
        if ($lock) {
            $query->lockForUpdate();
        }

        return $query->first();
    }

    /** Create session state only after locked canonical proof and pipeline checks. */
    private function finishStatefulLogin(SubjectReference $reference, #[SensitiveParameter] string $passwordHash, bool $factorVerified, AuthenticationRequestContext $requestContext, bool $remember, StatefulGuard $guard, Session $session): Authenticatable
    {
        $principal = $this->freshPrincipal($reference);
        $connection = $principal->getConnection();
        $guardMutationStarted = false;
        try {
            return $connection->transaction(function () use ($reference, $passwordHash, $factorVerified, $requestContext, $remember, $guard, $session, &$guardMutationStarted): Authenticatable {
                $principal = $this->eligibleCredentialPrincipal($reference, $passwordHash, $factorVerified, lock: true);
                $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', ['identifier_name' => $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email')), 'method' => AuthenticationPurpose::CredentialLogin->value, 'remember' => $remember], $reference), fn (): Authenticatable => $principal);
                if (SubjectReference::fromAuthenticatable($authenticated) != $reference) {
                    throw new AuthException('login_rejected', 'The login pipeline changed the authenticated principal.', 422);
                }
                $principal = $this->eligibleCredentialPrincipal($reference, $passwordHash, $factorVerified);
                $guardMutationStarted = true;
                $guard->login($principal, $remember);
                $session->regenerate(true);
                $this->loginMetadata->record($principal, $requestContext);
                $this->audits->record('authentication.succeeded', subject: $reference, actor: $principal, metadata: ['method' => AuthenticationPurpose::CredentialLogin->value]);
                $this->ownerSelection->select($principal, $requestContext, OwnerAuthenticationPurpose::Login);
                $this->domainEvents->dispatch(new UserAuthenticated($reference), $principal->getConnection());

                return $principal;
            });
        } catch (Throwable $exception) {
            if ($guardMutationStarted) {
                $guard->logout();
            }
            throw $exception;
        }
    }

    /** Verify an enrolled native factor without accepting caller-provided verification flags.
     * @param  array{code?: mixed, recoveryCode?: mixed}  $proof
     */
    private function verifyLoginFactor(Authenticatable $subject, #[SensitiveParameter] array $proof): bool
    {
        if (array_diff(array_keys($proof), ['code', 'recoveryCode']) !== [] || count($proof) > 1) {
            throw new \InvalidArgumentException('Unknown or conflicting factor proof.');
        }
        foreach ($proof as $value) {
            if (! is_string($value) || trim($value) === '' || strlen($value) > 128) {
                throw new \InvalidArgumentException('Factor proof must be a bounded non-empty string.');
            }
        }
        if (! $this->requiresSecondFactor($subject)) {
            return false;
        }
        if (isset($proof['code'])) {
            $this->secondFactor->verify($subject, ['code' => $proof['code']]);
        } elseif (isset($proof['recoveryCode'])) {
            $this->secondFactor->consumeRecoveryCode($subject, ['code' => $proof['recoveryCode']]);
        } else {
            throw new AuthException('second_factor_required', 'An enrolled second factor is required.', 422);
        }

        return true;
    }

    /** Resolve the configured persisted principal rather than trusting pipeline or caller state. */
    private function freshPrincipal(SubjectReference $reference, bool $lock = false): User
    {
        $class = $this->models->userClass();
        if ($reference->type !== (new $class)->getMorphClass()) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $query = $class::query()->useWritePdo();
        if ($lock) {
            $query->lockForUpdate();
        }
        $principal = $query->find($reference->identifier);
        if ($principal === null) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }

        return $principal;
    }

    /** Recheck the persisted credential, eligibility and enrolled-factor requirements at each success boundary. */
    private function eligibleCredentialPrincipal(SubjectReference $reference, #[SensitiveParameter] string $passwordHash, bool $factorVerified, bool $lock = false): User
    {
        $principal = $this->freshPrincipal($reference, $lock);
        if (! hash_equals($passwordHash, $principal->getAuthPassword())) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $this->eligibility->assertEligible($principal, AuthenticationPurpose::CredentialLogin);
        if (! $factorVerified && $this->requiresSecondFactor($principal)) {
            throw new AuthException('second_factor_required', 'An enrolled second factor is required.', 422);
        }

        return $principal;
    }

    /** Determine the active native enrollment requirement without accessing browser state. */
    private function requiresSecondFactor(Authenticatable $principal): bool
    {
        return $this->configuration->featureEnabled(AuthFeature::Totp)
            && $this->secondFactor->state($principal)['confirmedCredentials'] > 0;
    }
}
