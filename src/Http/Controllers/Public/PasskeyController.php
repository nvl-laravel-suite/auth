<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyAuthenticationAction;
use Nvl\Auth\Data\Mutations\FinishPasskeyAuthenticationData;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Handles public passkey authentication ceremonies.
 */
final class PasskeyController
{
    use InteractsWithValidatedInput;

    /**
     * Begin a discoverable passkey ceremony.
     */
    public function begin(
        Request $request,
        BeginPasskeyAuthenticationAction $action,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $options = $action->execute(tenant: $this->requestedTenant($request, $tenants));

        return response()->json([
            'data' => ['ceremony_id' => $options->ceremonyId, 'options' => $options->options, 'expires_at' => $options->expiresAt->toIso8601String()],
            'code' => 'passkey_authentication_started',
            'message' => 'The passkey ceremony was started.',
        ]);
    }

    /**
     * Finish a passkey assertion and establish a Laravel session.
     */
    public function finish(
        FinishPasskeyAuthenticationData $data,
        Request $request,
        FinishPasskeyAuthenticationAction $action,
        EstablishAuthenticatedSessionAction $sessions,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        $completed = $action->execute($data, $this->requestedTenant($request, $tenants));
        $sessions->execute($completed->subject, requestContext: new AuthenticationRequestContext(
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            requestId: $request->header('X-Request-ID'),
            tenantIntentNonce: $completed->requestContext?->tenantIntentNonce,
            tenantSessionBinding: $completed->requestContext?->tenantSessionBinding,
            tenantPurpose: $completed->requestContext?->tenantPurpose,
            tenantProvider: $completed->requestContext?->tenantProvider,
            tenantIntentTenant: $completed->requestContext?->tenantIntentTenant,
            tenantIntentExpiresAt: $completed->requestContext?->tenantIntentExpiresAt,
            requestedTenant: $completed->requestContext?->requestedTenant,
            tenantIntentSubjectBound: $completed->requestContext instanceof AuthenticationRequestContext
                && $completed->requestContext->tenantIntentSubjectBound,
        ));

        return response()->json([
            'data' => ['subject' => ['type' => $completed->subject->type, 'id' => $completed->subject->identifier]],
            'code' => 'passkey_authenticated',
            'message' => 'Passkey authentication succeeded.',
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
}
