<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\FinishPasskeyRegistrationData;
use Spatie\LaravelData\Optional;

/**
 * Handles authenticated passkey registration and revocation transport.
 */
final class PasskeyController extends AuthenticatedController
{
    /**
     * Begin passkey registration.
     */
    public function begin(Request $request, AuthPasskeys $action): JsonResponse
    {
        $options = $action->beginRegistration($this->subject($request));

        return response()->json([
            'data' => ['ceremony_id' => $options->ceremonyId, 'options' => $options->options, 'expires_at' => $options->expiresAt->toIso8601String()],
            'code' => 'passkey_registration_started', 'message' => trans('nvl-auth::responsecode.passkey_registration_started'),
        ]);
    }

    /**
     * Finish passkey registration.
     */
    public function finish(FinishPasskeyRegistrationData $data, Request $request, AuthPasskeys $action): JsonResponse
    {
        $passkey = $action->finishRegistration(
            $this->subject($request),
            array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional),
        );

        return response()->json([
            'data' => ['passkey_id' => $passkey->identifier(), 'name' => $passkey->name],
            'code' => 'passkey_registered', 'message' => trans('nvl-auth::responsecode.passkey_registered'),
        ], 201);
    }

    /**
     * Revoke one passkey.
     */
    public function revoke(
        Request $request,
        Passkey $passkey,
        AuthPasskeys $action,
    ): JsonResponse {
        $action->revoke($this->subject($request), $passkey);

        return response()->json(['data' => null, 'code' => 'passkey_revoked', 'message' => trans('nvl-auth::responsecode.passkey_revoked')]);
    }
}
