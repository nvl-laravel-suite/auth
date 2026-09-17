<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Actions\Challenges\ConsumeMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAuthenticationAction;
use Nvl\Auth\Actions\Challenges\RequestSecurityCodeAuthenticationAction;
use Nvl\Auth\Actions\Challenges\VerifySecurityCodeAction;
use Nvl\Auth\Data\Mutations\ConsumeMagicLinkData;
use Nvl\Auth\Data\Mutations\RequestMagicLinkData;
use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Data\Mutations\VerifySecurityCodeData;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\Services\TenantAuthenticationChallengeIntents;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Handles magic-link and numeric-code challenge transports.
 */
final class ChallengeController
{
    use InteractsWithValidatedInput;

    /**
     * Request a magic link without returning its secret.
     */
    public function requestMagicLink(
        RequestMagicLinkData $data,
        Request $request,
        RequestMagicLinkAuthenticationAction $action,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $action->execute($data, $request->getPreferredLanguage(), $this->requestedTenant($request, $tenants));

        return response()->json(['data' => null, 'code' => 'magic_link_requested', 'message' => 'The magic link was requested.'], 202);
    }

    /**
     * Consume a magic link and establish a session when it is subject-bound.
     */
    public function consumeMagicLink(
        ConsumeMagicLinkData $data,
        Request $request,
        ConsumeMagicLinkAction $action,
        EstablishAuthenticatedSessionAction $sessions,
        TenantAuthenticationChallengeIntents $tenantIntents,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $challenge = $action->execute($data);

        if (is_string($challenge->subject_type) && is_string($challenge->subject_id)) {
            $sessions->execute(
                new SubjectReference($challenge->subject_type, $challenge->subject_id),
                requestContext: $this->requestContext(
                    $request,
                    $tenantIntents->context($challenge, $this->requestedTenant($request, $tenants)),
                ),
                purpose: AuthenticationPurpose::PasswordlessLogin,
            );
        }

        return response()->json(['data' => null, 'code' => 'magic_link_consumed', 'message' => 'The magic link was consumed.']);
    }

    /**
     * Request a numeric security code.
     */
    public function requestSecurityCode(
        RequestSecurityCodeData $data,
        Request $request,
        RequestSecurityCodeAuthenticationAction $action,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $action->execute(
            $data,
            locale: $request->getPreferredLanguage(),
            tenant: $this->requestedTenant($request, $tenants),
        );

        return response()->json(['data' => null, 'code' => 'security_code_requested', 'message' => 'The security code was requested.'], 202);
    }

    /**
     * Verify and consume a numeric security code.
     */
    public function verifySecurityCode(
        VerifySecurityCodeData $data,
        Request $request,
        VerifySecurityCodeAction $action,
        EstablishAuthenticatedSessionAction $sessions,
        TenantAuthenticationChallengeIntents $tenantIntents,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $challenge = $action->execute($data);
        if (is_string($challenge->subject_type) && is_string($challenge->subject_id)) {
            $context = $tenantIntents->context($challenge, $this->requestedTenant($request, $tenants));
            $sessions->execute(
                new SubjectReference($challenge->subject_type, $challenge->subject_id),
                requestContext: $this->requestContext($request, $context),
                purpose: AuthenticationPurpose::PasswordlessLogin,
            );
        }

        return response()->json([
            'data' => ['challenge_id' => $challenge->identifier()],
            'code' => 'security_code_verified',
            'message' => 'The security code was verified.',
        ]);
    }

    private function requestedTenant(Request $request, TenantHttpResolver $tenants): ?TenantId
    {
        if (config('tenancy.enabled') !== true) {
            return null;
        }

        try {
            return $tenants->resolve($request);
        } catch (TenantBoundaryViolation|TenantNotFound) {
            return null;
        }
    }

    private function requestContext(Request $request, ?AuthenticationRequestContext $tenant): AuthenticationRequestContext
    {
        return new AuthenticationRequestContext(
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            requestId: $request->header('X-Request-ID'),
            tenantIntentNonce: $tenant?->tenantIntentNonce,
            tenantSessionBinding: $tenant?->tenantSessionBinding,
            tenantPurpose: $tenant?->tenantPurpose,
            tenantProvider: $tenant?->tenantProvider,
            requestedTenant: $tenant?->requestedTenant,
            tenantIntentSubjectBound: $tenant instanceof AuthenticationRequestContext
                && $tenant->tenantIntentSubjectBound,
        );
    }
}
