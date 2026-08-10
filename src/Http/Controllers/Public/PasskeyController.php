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

/**
 * Handles public passkey authentication ceremonies.
 */
final class PasskeyController
{
    use InteractsWithValidatedInput;

    /**
     * Begin a discoverable passkey ceremony.
     */
    public function begin(BeginPasskeyAuthenticationAction $action): JsonResponse
    {
        $options = $action->execute();

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
    ): JsonResponse {
        $reference = $action->execute($data);
        $sessions->execute($reference, requestContext: new AuthenticationRequestContext(
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            requestId: $request->header('X-Request-ID'),
        ));

        return response()->json([
            'data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]],
            'code' => 'passkey_authenticated',
            'message' => 'Passkey authentication succeeded.',
        ]);
    }
}
