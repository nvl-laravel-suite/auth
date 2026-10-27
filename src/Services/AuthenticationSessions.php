<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
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
use Nvl\Support\Auth\CanonicalActorResolver;
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
    public function __construct(private FeatureGate $features, private OwnerAuthenticationSelection $ownerSelection, private AuthPipeline $pipeline, private AuthenticationEligibility $eligibility, private SuccessfulLoginMetadataRecorder $loginMetadata, private AuthAuditRecorder $audits, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents, private CanonicalActorResolver $actors) {}

    /**
     * Resolve and log in a referenced host subject.
     */
    public function establish(Authenticatable $principal, StatefulGuard $guard, Session $session, bool $remember = false): void
    {
        $this->establishForPurpose($principal, $guard, $session, AuthenticationPurpose::PasswordlessLogin, new AuthenticationRequestContext, $remember);
    }

    /**
     * Internal orchestration after the adapter has verified its identity proof.
     *
     * @internal The host must never accept the purpose from transport input.
     */
    public function establishForPurpose(Authenticatable $principal, StatefulGuard $guard, Session $session, AuthenticationPurpose $purpose, AuthenticationRequestContext $requestContext, bool $remember = false): void
    {
        $subject = $principal;
        $reference = SubjectReference::fromAuthenticatable($principal);
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::Login);
        $this->operations->central(AuthIdentityOperation::Login, $subject);
        $this->domainEvents->dispatch(new AuthenticationAttempted('subject_reference', $reference->identifier), (new AuthAudit)->getConnection());
        $guardMutationStarted = false;
        try {
            $subject = $this->fresh($subject, $purpose);
            $connection = $subject instanceof Model ? $subject->getConnection() : (new AuthAudit)->getConnection();
            $connection->transaction(function () use ($subject, $purpose, $reference, $remember, $guard, $session, $requestContext, &$guardMutationStarted): void {
                $canonical = $this->fresh($subject, $purpose, lock: true);
                $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', ['method' => $purpose->value, 'remember' => $remember], $reference), fn (): Authenticatable => $canonical);
                if ($authenticated::class !== $canonical::class || SubjectReference::fromAuthenticatable($authenticated) != $reference) {
                    throw new AuthException('login_rejected', 'The login pipeline changed the authenticated principal.', 422);
                }
                $canonical = $this->fresh($canonical, $purpose);
                $guardMutationStarted = true;
                $guard->login($canonical, $remember);
                $session->regenerate(true);
                $this->loginMetadata->record($canonical, $requestContext);
                $this->audits->record('authentication.succeeded', subject: $reference, actor: $canonical, metadata: ['method' => $purpose->value]);
                $this->ownerSelection->select($canonical, $requestContext, $purpose === AuthenticationPurpose::SocialLogin ? OwnerAuthenticationPurpose::SocialLogin : $requestContext->ownerPurpose ?? OwnerAuthenticationPurpose::Login);
                $this->domainEvents->dispatch(new UserAuthenticated($reference), $canonical instanceof Model ? $canonical->getConnection() : (new AuthAudit)->getConnection());
            });

            return;
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

    /** Recheck canonical persistence before host eligibility, preserving non-Eloquent host identity contracts. */
    private function fresh(Authenticatable $subject, AuthenticationPurpose $purpose, bool $lock = false): Authenticatable
    {
        try {
            $canonical = $this->actors->resolve($subject, $lock);
        } catch (AuthorizationException $exception) {
            throw new AuthException('subject_unavailable', 'The authenticated subject is unavailable.', 404, previous: $exception);
        }
        $this->eligibility->assertEligible($canonical, $purpose);

        return $canonical;
    }
}
