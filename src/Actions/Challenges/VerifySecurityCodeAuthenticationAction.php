<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Data\Mutations\VerifySecurityCodeData;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\TenantAuthenticationChallengeIntents;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Verifies an explicitly passwordless security code and establishes its subject session.
 *
 * Delegation to the generic verification and session Actions is deliberate domain
 * orchestration: this entry point alone turns security-code proof into authentication.
 */
final readonly class VerifySecurityCodeAuthenticationAction
{
    /** Create the subject-bound passwordless verification use case. */
    public function __construct(
        private FeatureGate $features,
        private VerifySecurityCodeAction $codes,
        private TenantAuthenticationChallengeIntents $tenantIntents,
        private EstablishAuthenticatedSessionAction $sessions,
    ) {}

    /** Verify a passwordless code and establish the referenced subject session. */
    public function execute(
        VerifySecurityCodeData $data,
        AuthenticationRequestContext $requestContext,
    ): Challenge {
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Use);
        if ($data->purpose !== AuthenticationPurpose::PasswordlessLogin->value) {
            throw new AuthException(
                'security_code_authentication_purpose_invalid',
                'Security-code authentication requires the passwordless login purpose.',
                422,
            );
        }

        $challenge = $this->codes->execute($data);
        if (! is_string($challenge->subject_type) || ! is_string($challenge->subject_id)) {
            throw new AuthException('subject_unavailable', 'The authentication subject is unavailable.', 404);
        }
        $tenant = $this->tenantIntents->context($challenge, $requestContext->requestedTenant);
        $this->sessions->execute(
            new SubjectReference($challenge->subject_type, $challenge->subject_id),
            requestContext: new AuthenticationRequestContext(
                ipAddress: $requestContext->ipAddress,
                userAgent: $requestContext->userAgent,
                requestId: $requestContext->requestId,
                tenantIntentNonce: $tenant?->tenantIntentNonce,
                tenantSessionBinding: $tenant?->tenantSessionBinding,
                tenantPurpose: $tenant?->tenantPurpose,
                tenantProvider: $tenant?->tenantProvider,
                requestedTenant: $tenant?->requestedTenant,
                tenantIntentSubjectBound: $tenant instanceof AuthenticationRequestContext
                    && $tenant->tenantIntentSubjectBound,
            ),
            purpose: AuthenticationPurpose::PasswordlessLogin,
        );

        return $challenge;
    }
}
