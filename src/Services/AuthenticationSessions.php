<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Events\UserLoggedOut;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;
use Throwable;

/**
 * Establishes a Laravel session after passwordless identity proof succeeds.
 *
 * @api
 */
final readonly class AuthenticationSessions
{
    /**
     * Create the session establishment use case.
     */
    public function __construct(private FeatureGate $features, private OwnerAuthenticationSelection $ownerSelection, private AuthPipeline $pipeline, private SuccessfulLoginMetadataRecorder $loginMetadata, private AuthAuditRecorder $audits, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents, private AuthenticationProofs $proofs, private AuthManager $auth, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private StatefulAuthenticationBoundary $boundary, private AuthModelRegistry $models, private PrincipalSecurity $security, private SecretHasher $hasher) {}

    private const string PendingFactorLogin = 'nvl-auth.credential_login';

    /** Admit an immediate browser transition before primary verifiers or transport effects. */
    public function assertCanTransition(?Authenticatable $subject = null): void
    {
        if ($this->configuration->featureEnabled(AuthFeature::ManagedSessions)) {
            if (config('session.driver') === 'cookie' || config('session.driver') === 'array' && config('app.env') !== 'testing') {
                throw AuthException::invalidConfiguration('Managed sessions require a server-side driver; array is test-only.');
            }
            $browser = new BrowserSession;
            $this->boundary->assertOutsideTransaction($browser->getConnection());
            if (! $browser->getConnection()->getSchemaBuilder()->hasColumns($browser->getTable(), ['binding_hash', 'provider_hash', 'security_revision', 'absolute_expires_at'])) {
                throw AuthException::invalidConfiguration('Managed session schema is missing; run the forward migration before enabling.');
            }
        }
        $this->boundary->assertOutsideTransaction((new Challenge)->getConnection());
        $this->boundary->assertOutsideTransaction((new AuthAudit)->getConnection());
        $class = $this->models->userClass();
        $this->boundary->assertOutsideTransaction((new $class)->getConnection());
        if ($subject instanceof Model) {
            $this->boundary->assertOutsideTransaction($subject->getConnection());
        }
        $provider = $this->auth->createUserProvider($this->configuration->string('provider', 'users'));
        if ($provider instanceof EloquentUserProvider) {
            $this->boundary->assertOutsideTransaction($provider->createModel()->getConnection());
        }
    }

    /** Consume a native browser capability, applying mandatory assurance before guard mutation. */
    public function establishFromProof(#[\SensitiveParameter] string $proof, StatefulGuard $guard, Session $session, AuthenticationRequestContext $context, bool $remember = false): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->assertCanTransition();
        $context->assertBound(AuthenticationDestination::Session);
        if ($remember && $this->configuration->featureEnabled(AuthFeature::ManagedSessions)) {
            throw AuthException::invalidConfiguration('Managed remember authentication requires the explicit managed guard adapter.');
        }
        if ($context->sessionBinding !== $session->getId() || $this->auth->guard($context->guardName) !== $guard) {
            throw new AuthException('authentication_binding_invalid', 'The authentication browser binding does not match.', 422);
        }
        try {
            $consumed = $this->proofs->consumeForFinalization($proof, AuthenticationDestination::Session, $context);
        } catch (AuthException $exception) {
            if ($exception->errorCode === 'second_factor_required') {
                $session->put(self::PendingFactorLogin, ['proof' => $proof, 'requestContext' => $context, 'remember' => $remember]);
                $guard->logout();
            } else {
                $this->audits->record('authentication.rejected', outcome: 'failure', metadata: ['reason' => $exception->errorCode]);
                $this->domainEvents->dispatch(new AuthenticationRejected('subject_reference', '', $exception->errorCode), (new AuthAudit)->getConnection());
            }
            throw $exception;
        }
        $session->forget(self::PendingFactorLogin);
        $subject = $consumed['subject'];
        $evidence = $consumed['evidence'];
        $verification = $consumed['verification'];
        $reference = $evidence->subject;
        $purpose = $evidence->method->purpose();
        $requestContext = $evidence->context;
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->assertCanTransition();
        $this->operations->central(AuthIdentityOperation::Login);
        $this->operations->central(AuthIdentityOperation::Login, $subject);
        if ($evidence->method !== AuthenticationMethod::Password) {
            $this->domainEvents->dispatch(new AuthenticationAttempted('subject_reference', $reference->identifier), (new AuthAudit)->getConnection());
        }
        $guardMutationStarted = false;
        try {
            $subject = $consumed['subject'];
            $connection = $subject->getConnection();

            return $connection->transaction(function () use ($purpose, $reference, $remember, $guard, $session, $requestContext, $evidence, $verification, &$guardMutationStarted): Authenticatable {
                $canonical = $this->proofs->recheck($verification);
                $attributes = ['method' => $purpose->value, 'remember' => $remember];
                if ($evidence->method === AuthenticationMethod::Password) {
                    $attributes['identifier_name'] = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
                }
                $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', $attributes, $reference), fn (): Authenticatable => $canonical);
                if ($authenticated::class !== $canonical::class || SubjectReference::fromAuthenticatable($authenticated) != $reference) {
                    throw new AuthException('login_rejected', 'The login pipeline changed the authenticated principal.', 422);
                }
                $canonical = $this->proofs->recheck($verification);
                $guardMutationStarted = true;
                $guard->login($canonical, $remember);
                if (! $session->regenerate(true)) {
                    throw new AuthException('session_transition_failed', 'Browser session rotation failed.', 500);
                }
                $this->loginMetadata->record($canonical, $requestContext);
                $canonical = $this->proofs->recheck($verification);
                $this->recordManagedSession($canonical, $session, $evidence);
                $this->audits->record('authentication.succeeded', subject: $reference, actor: $canonical, metadata: ['method' => $purpose->value]);
                $this->ownerSelection->select($canonical, $requestContext, $purpose === AuthenticationPurpose::SocialLogin ? OwnerAuthenticationPurpose::SocialLogin : $requestContext->ownerPurpose ?? OwnerAuthenticationPurpose::Login);
                $this->domainEvents->dispatch(new UserAuthenticated($reference), $canonical->getConnection());

                return $canonical;
            });
        } catch (Throwable $exception) {
            if ($guardMutationStarted) {
                try {
                    $guard->logout();
                } finally {
                    if ($guard instanceof SessionGuard) {
                        $guard->forgetUser();
                    }
                    try {
                        $session->invalidate();
                    } finally {
                        $session->regenerateToken();
                    }
                }
            }
            $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
            $this->audits->record('authentication.rejected', outcome: 'failure', subject: $reference, actor: $subject, metadata: ['method' => $purpose->value, 'reason' => $reason]);
            $this->domainEvents->dispatch(new AuthenticationRejected('subject_reference', $reference->identifier, $reason, $reference), (new AuthAudit)->getConnection());
            throw $exception;
        }
    }

    /** Private enrollment is reachable only after native proof consumption and final freshness checks. */
    private function recordManagedSession(Authenticatable $subject, Session $session, AuthenticationEvidence $evidence): void
    {
        if (! $this->configuration->featureEnabled(AuthFeature::ManagedSessions)) {
            return;
        }
        if (! $subject instanceof Model || $subject->getConnection() !== (new BrowserSession)->getConnection()) {
            throw AuthException::invalidConfiguration('Managed session enrollment requires one source.');
        }
        $reference = SubjectReference::fromAuthenticatable($subject);
        $guard = $evidence->context->guardName;
        if ($guard === null) {
            throw AuthException::invalidConfiguration('Managed session enrollment requires a selected guard.');
        }
        $key = AuthBrowserSessions::bindingKey($guard);
        $old = $session->get($key);
        if (is_string($old)) {
            BrowserSession::query()->where('binding_hash', $this->hasher->hash('native-browser-binding', $old))->where('guard_name', $guard)->whereNull('revoked_at')->update(['revoked_at' => now()]);
        }
        $binding = bin2hex(random_bytes(32));
        $now = CarbonImmutable::now('UTC');
        $entry = BrowserSession::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'guard_name' => $guard, 'provider_hash' => AuthBrowserSessions::providerFingerprint($guard), 'binding_hash' => $this->hasher->hash('native-browser-binding', $binding), 'security_revision' => $this->security->lock($subject)->revision, 'session_family_id' => (string) Str::uuid(), 'method' => $evidence->method->value, 'assurance' => ['factors' => $evidence->factors], 'authenticated_at' => $now, 'last_seen_at' => $now, 'absolute_expires_at' => $now->addSeconds($this->configuration->integerBetween('features.managed_sessions.settings.absolute_lifetime_seconds', 43200, 300, 2592000)), 'ip_address' => $evidence->context->ipAddress, 'user_agent' => $evidence->context->userAgent]);
        $session->put($key, $binding);
        $session->put($key.'-id', $entry->identifier());
    }

    /** Native Auth operation. */
    public function logout(StatefulGuard $guard, Session $session, ?string $guardName = null): void
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Revoke);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $this->assertCanTransition();
        $guardName ??= $this->configuration->string('guard', 'web');
        if ($this->configuration->featureEnabled(AuthFeature::ManagedSessions) && $this->auth->guard($guardName) !== $guard) {
            throw new AuthException('authentication_binding_invalid', 'The selected logout guard does not match.', 422);
        }
        $subject = $guard->user();
        $this->assertCanTransition($subject);
        $this->operations->central(AuthIdentityOperation::Logout);
        $reference = $subject instanceof Authenticatable ? SubjectReference::fromAuthenticatable($subject) : null;
        $this->pipeline->run('logout', new AuthPipelineContext('logout', subject: $reference), function () use ($guard, $session, $reference, $subject, $guardName): void {
            $this->assertCanTransition($subject);
            if ($this->configuration->featureEnabled(AuthFeature::ManagedSessions)) {
                $binding = $session->get(AuthBrowserSessions::bindingKey($guardName));
                if (is_string($binding)) {
                    BrowserSession::query()->where('binding_hash', $this->hasher->hash('native-browser-binding', $binding))->where('guard_name', $guardName)->whereNull('revoked_at')->update(['revoked_at' => now()]);
                }
            }
            try {
                $guard->logout();
            } finally {
                if ($guard instanceof SessionGuard) {
                    $guard->forgetUser();
                }
                try {
                    $session->invalidate();
                } finally {
                    $session->regenerateToken();
                }
            }
            $this->audits->record('authentication.logged_out', subject: $reference, actor: $subject instanceof Authenticatable ? $subject : null);
            $this->domainEvents->dispatch(new UserLoggedOut($reference), (new AuthAudit)->getConnection());
        });
    }

    /** @param array{code?: mixed, recoveryCode?: mixed} $factorProof */
    public function completeSecondFactor(#[\SensitiveParameter] array $factorProof, StatefulGuard $guard, Session $session): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->assertCanTransition();
        $pending = $session->get(self::PendingFactorLogin);
        if (! is_array($pending) || ! is_string($pending['proof'] ?? null) || ! ($pending['requestContext'] ?? null) instanceof AuthenticationRequestContext || ! is_bool($pending['remember'] ?? null)) {
            throw new AuthException('login_challenge_invalid', 'The login continuation is unavailable.', 422);
        }
        $context = $pending['requestContext'];
        if ($context->sessionBinding !== $session->getId() || $this->auth->guard($context->guardName) !== $guard) {
            throw new AuthException('authentication_binding_invalid', 'The authentication browser binding does not match.', 422);
        }
        $proof = $this->proofs->completeFactor($pending['proof'], AuthenticationDestination::Session, $context, $factorProof);

        return $this->establishFromProof($proof->reveal(), $guard, $session, $context, $pending['remember']);
    }

    public function hasPendingSecondFactor(Session $session): bool
    {
        $pending = $session->get(self::PendingFactorLogin);

        return is_array($pending) && is_string($pending['proof'] ?? null) && $this->proofs->available($pending['proof']);
    }
}
