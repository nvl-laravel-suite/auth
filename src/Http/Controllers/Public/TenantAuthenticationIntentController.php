<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\CompletePendingTenantAuthenticationIntentAction;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Http\PackageExceptionPayload;
use Nvl\Support\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Support\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Support\Tenancy\Exceptions\TenantNotFound;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Completes server-owned post-authentication tenant selection.
 */
final readonly class TenantAuthenticationIntentController
{
    public function __construct(private PackageExceptionPayload $payload) {}

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
            $payload = $this->payload->for($exception);

            return response()->json([
                'data' => null,
                'code' => $payload['code'],
                'message' => $payload['message'],
            ], $exception->status, $this->payload->headers($exception));
        }

        return response()->json([
            'data' => ['tenant_id' => $tenant->value],
            'code' => 'tenant_authentication_intent_completed', 'message' => trans('nvl-auth::responsecode.tenant_authentication_intent_completed'),
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
