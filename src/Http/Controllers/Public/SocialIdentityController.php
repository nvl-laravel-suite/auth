<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Actions\SocialIdentities\CompleteSocialAuthorizationAction;
use Nvl\Auth\Actions\SocialIdentities\StartSocialAuthorizationAction;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\Exceptions\TenantNotFound;

/**
 * Handles public Socialite authorization and callback transport.
 */
final class SocialIdentityController
{
    /**
     * Return an allowlisted provider authorization URL.
     */
    public function redirect(
        string $provider,
        Request $request,
        StartSocialAuthorizationAction $action,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $tenant = null;
        if (config('tenancy.enabled') === true) {
            try {
                $tenant = $tenants->resolve($request);
            } catch (TenantBoundaryViolation|TenantNotFound) {
                $tenant = null;
            }
        }
        $returnPath = $request->query('return_path');

        return response()->json([
            'data' => ['url' => $action->execute(
                $provider,
                $tenant,
                is_string($returnPath) ? $returnPath : null,
            )],
            'code' => 'social_authorization_started',
            'message' => 'Social authorization was started.',
        ]);
    }

    /**
     * Complete provider authorization and establish a Laravel session.
     */
    public function callback(
        string $provider,
        Request $request,
        CompleteSocialAuthorizationAction $action,
        EstablishAuthenticatedSessionAction $sessions,
    ): JsonResponse {
        $state = $request->query('state');
        $identity = $action->execute(
            $provider,
            flowReference: is_string($state) ? $state : null,
        );
        $reference = new SubjectReference($identity->subject_type, $identity->subject_id);
        $sessions->execute(
            $reference,
            requestContext: new AuthenticationRequestContext(
                ipAddress: $request->ip(),
                userAgent: $request->userAgent(),
                requestId: $request->header('X-Request-ID'),
            ),
            purpose: AuthenticationPurpose::SocialLogin,
        );

        return response()->json([
            'data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]],
            'code' => 'social_authenticated',
            'message' => 'Social authentication succeeded.',
        ]);
    }
}
