<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\CompletePendingTenantAuthenticationIntentAction;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Completes server-owned post-authentication tenant selection.
 */
final class TenantAuthenticationIntentController
{
    /** Complete the current authenticated session's pending tenant intent. */
    public function complete(
        Request $request,
        CompletePendingTenantAuthenticationIntentAction $action,
        TenantHttpResolver $tenants,
    ): JsonResponse {
        try {
            if ($request->all() !== []) {
                throw new AuthException(
                    'tenant_authentication_intent_input_invalid',
                    'Tenant intent completion does not accept client intent state.',
                    422,
                );
            }
            $tenant = $action->execute($this->requestedTenant($request, $tenants));
        } catch (AuthException $exception) {
            return response()->json([
                'data' => null,
                'code' => $exception->errorCode,
                'message' => $exception->getMessage(),
            ], $exception->status);
        }

        return response()->json([
            'data' => ['tenant_id' => $tenant->value],
            'code' => 'tenant_authentication_intent_completed',
            'message' => 'Tenant selection succeeded.',
        ]);
    }

    /** Resolve only a trusted server-side tenant selector. */
    private function requestedTenant(Request $request, TenantHttpResolver $tenants): ?TenantId
    {
        try {
            return $tenants->resolve($request);
        } catch (TenantBoundaryViolation|TenantNotFound) {
            return null;
        }
    }
}
