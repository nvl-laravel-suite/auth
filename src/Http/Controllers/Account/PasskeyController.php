<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\RevokePasskeyAction;
use Nvl\Auth\Models\Passkey;

/**
 * Handles authenticated passkey registration and revocation transport.
 */
final class PasskeyController extends AuthenticatedController
{
    /**
     * Begin passkey registration.
     */
    public function begin(Request $request, BeginPasskeyRegistrationAction $action): JsonResponse
    {
        $options = $action->execute($this->subject($request));

        return response()->json([
            'data' => ['ceremony_id' => $options->ceremonyId, 'options' => $options->options, 'expires_at' => $options->expiresAt->toIso8601String()],
            'code' => 'passkey_registration_started',
            'message' => 'Passkey registration was started.',
        ]);
    }

    /**
     * Finish passkey registration.
     */
    public function finish(Request $request, FinishPasskeyRegistrationAction $action): JsonResponse
    {
        $request->validate([
            'ceremony_id' => ['required', 'string', 'max:191'],
            'response' => ['required', 'array'],
            'name' => ['sometimes', 'nullable', 'string', 'max:120'],
        ]);
        $passkey = $action->execute(
            $this->subject($request),
            $this->stringInput($request, 'ceremony_id'),
            $this->associativeInput($request, 'response'),
            $this->optionalStringInput($request, 'name'),
        );

        return response()->json([
            'data' => ['passkey_id' => $passkey->identifier(), 'name' => $passkey->name],
            'code' => 'passkey_registered',
            'message' => 'The passkey was registered.',
        ], 201);
    }

    /**
     * Revoke one passkey.
     */
    public function revoke(
        Request $request,
        Passkey $passkey,
        RevokePasskeyAction $action,
    ): JsonResponse {
        $action->execute($this->subject($request), $passkey);

        return response()->json(['data' => null, 'code' => 'passkey_revoked', 'message' => 'The passkey was revoked.']);
    }
}
