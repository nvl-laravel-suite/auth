<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Establishes a Laravel session after passwordless identity proof succeeds.
 */
final readonly class EstablishAuthenticatedSessionAction
{
    /**
     * Create the session establishment use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthSubjectResolver $subjects,
        private AuthManager $auth,
        private BrowserSession $session,
        private AuthPipeline $pipeline,
        private AuthenticationEligibility $eligibility,
        private SuccessfulLoginMetadataRecorder $loginMetadata,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Resolve and log in a referenced host subject.
     */
    public function execute(
        SubjectReference $reference,
        bool $remember = false,
        ?AuthenticationRequestContext $requestContext = null,
        AuthenticationPurpose $purpose = AuthenticationPurpose::PasswordlessLogin,
    ): Authenticatable {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $subject = $this->subjects->resolve($reference);

        if (! $subject instanceof Authenticatable) {
            throw new AuthException('subject_unavailable', 'The authentication subject is unavailable.', 404);
        }

        $guard = $this->auth->guard($this->configuration->string('guard', 'web'));

        if (! $guard instanceof StatefulGuard) {
            throw AuthException::invalidConfiguration('Passwordless authentication requires a stateful guard.');
        }

        AuthenticationAttempted::dispatch('subject_reference', $reference->identifier);
        $guardMutationStarted = false;

        try {
            $this->eligibility->assertEligible($subject, $purpose);
            $authenticated = $this->pipeline->run(
                'login',
                new AuthPipelineContext(
                    'login',
                    ['method' => $purpose->value, 'remember' => $remember],
                    $reference,
                ),
                fn (): Authenticatable => $subject,
            );
            $guardMutationStarted = true;
            $guard->login($authenticated, $remember);
            $this->session->regenerateIdentifier();
            $this->loginMetadata->record($authenticated, $requestContext ?? new AuthenticationRequestContext);
            $this->audits->record(
                'authentication.succeeded',
                subject: $reference,
                actor: $authenticated,
                metadata: ['method' => $purpose->value],
            );
            UserAuthenticated::dispatch($reference);

            return $authenticated;
        } catch (Throwable $exception) {
            if ($guardMutationStarted) {
                $guard->logout();
            }
            $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
            $this->audits->record(
                'authentication.rejected',
                outcome: 'failure',
                subject: $reference,
                actor: $subject,
                metadata: ['method' => $purpose->value, 'reason' => $reason],
            );
            AuthenticationRejected::dispatch('subject_reference', $reference->identifier, $reason, $reference);

            throw $exception;
        }
    }
}
