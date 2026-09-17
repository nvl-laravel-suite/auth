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
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\ValueObjects\TenantId;
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
        private AuthOperationBoundary $operations,
        private TenantAuthenticationIntents $tenantIntents,
        private TenantMembershipAccess $tenantMemberships,
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
        $this->operations->central(AuthIdentityOperation::Login);
        $subject = $this->subjects->resolve($reference);

        if (! $subject instanceof Authenticatable) {
            throw new AuthException('subject_unavailable', 'The authentication subject is unavailable.', 404);
        }
        $this->operations->central(AuthIdentityOperation::Login, $subject);

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
            $this->selectTenant($authenticated, $reference, $requestContext);
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

    /** Keep successful global authentication independent from denied tenant selection. */
    private function selectTenant(
        Authenticatable $subject,
        SubjectReference $reference,
        ?AuthenticationRequestContext $context,
    ): void {
        if (config('tenancy.enabled') !== true
            || ! is_string($context?->tenantIntentNonce)
            || ! is_string($context->tenantSessionBinding)
            || $context->tenantPurpose === null) {
            return;
        }
        try {
            if (! $context->requestedTenant instanceof TenantId) {
                throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
            }
            $tenant = $this->tenantIntents->consume(
                $context->tenantIntentNonce,
                $context->tenantPurpose,
                $context->tenantSessionBinding,
                $context->requestedTenant,
                $context->tenantIntentSubjectBound ? $reference : null,
                $context->tenantProvider,
            );
            $this->tenantMemberships->assertMember($subject, $tenant);
            $this->audits->record(
                'authentication.tenant_selected',
                subject: $reference,
                actor: $subject,
                metadata: ['tenant_id' => $tenant->value],
            );
        } catch (Throwable) {
            $this->audits->record(
                'authentication.tenant_selection_denied',
                outcome: 'denied',
                subject: $reference,
                actor: $subject,
            );
        }
    }
}
