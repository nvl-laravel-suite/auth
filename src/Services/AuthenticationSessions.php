<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Contracts\AuthAuditRecorder;
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
use Nvl\Auth\Pipelines\AuthPipeline;
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
    public function __construct(private FeatureGate $features, private OwnerAuthenticationSelection $ownerSelection, private AuthPipeline $pipeline, private SuccessfulLoginMetadataRecorder $loginMetadata, private AuthAuditRecorder $audits, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents, private AuthenticationProofs $proofs, private AuthManager $auth) {}

    private const string PendingFactorLogin = 'nvl-auth.credential_login';

    /** Consume a native browser capability, applying mandatory assurance before guard mutation. */
    public function establishFromProof(#[\SensitiveParameter] string $proof, StatefulGuard $guard, Session $session, AuthenticationRequestContext $context, bool $remember = false): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $context->assertBound(AuthenticationDestination::Session);
        if ($context->sessionBinding !== $session->getId() || $this->auth->guard($context->guardName) !== $guard) {
            throw new AuthException('authentication_binding_invalid', 'The authentication browser binding does not match.', 422);
        }
        try {
            $consumed = $this->proofs->consume($proof, AuthenticationDestination::Session, $context);
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
        $reference = $evidence->subject;
        $purpose = $evidence->method->purpose();
        $requestContext = $evidence->context;
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::Login);
        $this->operations->central(AuthIdentityOperation::Login, $subject);
        if ($evidence->method !== AuthenticationMethod::Password) {
            $this->domainEvents->dispatch(new AuthenticationAttempted('subject_reference', $reference->identifier), (new AuthAudit)->getConnection());
        }
        $guardMutationStarted = false;
        try {
            $subject = $consumed['subject'];
            $connection = $subject->getConnection();

            return $connection->transaction(function () use ($purpose, $reference, $remember, $guard, $session, $requestContext, $evidence, &$guardMutationStarted): Authenticatable {
                $canonical = $this->proofs->recheck($evidence);
                $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', ['method' => $purpose->value, 'remember' => $remember], $reference), fn (): Authenticatable => $canonical);
                if ($authenticated::class !== $canonical::class || SubjectReference::fromAuthenticatable($authenticated) != $reference) {
                    throw new AuthException('login_rejected', 'The login pipeline changed the authenticated principal.', 422);
                }
                $canonical = $this->proofs->recheck($evidence);
                $guardMutationStarted = true;
                $guard->login($canonical, $remember);
                $session->regenerate(true);
                $this->loginMetadata->record($canonical, $requestContext);
                $canonical = $this->proofs->recheck($evidence);
                $this->audits->record('authentication.succeeded', subject: $reference, actor: $canonical, metadata: ['method' => $purpose->value]);
                $this->ownerSelection->select($canonical, $requestContext, $purpose === AuthenticationPurpose::SocialLogin ? OwnerAuthenticationPurpose::SocialLogin : $requestContext->ownerPurpose ?? OwnerAuthenticationPurpose::Login);
                $this->domainEvents->dispatch(new UserAuthenticated($reference), $canonical->getConnection());

                return $canonical;
            });
        } catch (Throwable $exception) {
            if ($guardMutationStarted) {
                $guard->logout();
            }
            $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
            $this->audits->record('authentication.rejected', outcome: 'failure', subject: $reference, actor: $subject, metadata: ['method' => $purpose->value, 'reason' => $reason]);
            $this->domainEvents->dispatch(new AuthenticationRejected('subject_reference', $reference->identifier, $reason, $reference), (new AuthAudit)->getConnection());
            throw $exception;
        }
    }

    /** Native Auth operation. */
    public function logout(StatefulGuard $guard, Session $session): void
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Revoke);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $this->operations->central(AuthIdentityOperation::Logout);
        $subject = $guard->user();
        $reference = $subject instanceof Authenticatable ? SubjectReference::fromAuthenticatable($subject) : null;
        $this->pipeline->run('logout', new AuthPipelineContext('logout', subject: $reference), function () use ($guard, $session, $reference, $subject): void {
            $guard->logout();
            $session->invalidate();
            $session->regenerateToken();
            $this->audits->record('authentication.logged_out', subject: $reference, actor: $subject instanceof Authenticatable ? $subject : null);
            $this->domainEvents->dispatch(new UserLoggedOut($reference), (new AuthAudit)->getConnection());
        });
    }

    /** @param array{code?: mixed, recoveryCode?: mixed} $factorProof */
    public function completeSecondFactor(#[\SensitiveParameter] array $factorProof, StatefulGuard $guard, Session $session): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
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
