<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Totp\ConfirmTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\RevokeTotpCredentialAction;
use Nvl\Auth\Actions\Totp\StartTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\VerifyTotpAction;
use Nvl\Auth\Models\TotpCredential;

/**
 * Handles authenticated TOTP enrollment and lifecycle transport.
 */
final class TotpController extends AuthenticatedController
{
    /**
     * Start TOTP enrollment.
     */
    public function start(Request $request, StartTotpEnrollmentAction $action): JsonResponse
    {
        $request->validate([
            'account_name' => ['required', 'string', 'max:255'],
            'name' => ['sometimes', 'nullable', 'string', 'max:120'],
        ]);
        $result = $action->execute(
            $this->subject($request),
            $this->stringInput($request, 'account_name'),
            $this->optionalStringInput($request, 'name'),
        );

        return response()->json([
            'data' => [
                'credential_id' => $result->credential->identifier(),
                'secret' => $result->secret,
                'provisioning_uri' => $result->provisioningUri,
            ],
            'code' => 'totp_enrollment_started',
            'message' => 'TOTP enrollment was started.',
        ], 201);
    }

    /**
     * Confirm TOTP enrollment.
     */
    public function confirm(
        Request $request,
        TotpCredential $credential,
        ConfirmTotpEnrollmentAction $action,
    ): JsonResponse {
        $request->validate(['code' => ['required', 'string', 'max:20']]);
        $confirmed = $action->execute(
            $this->subject($request),
            $credential,
            $this->stringInput($request, 'code'),
        );

        return response()->json(['data' => ['credential_id' => $confirmed->identifier()], 'code' => 'totp_enrolled', 'message' => 'TOTP was enrolled.']);
    }

    /**
     * Verify a current TOTP proof.
     */
    public function verify(Request $request, VerifyTotpAction $action): JsonResponse
    {
        $request->validate(['code' => ['required', 'string', 'max:20']]);
        $credential = $action->execute($this->subject($request), $this->stringInput($request, 'code'));

        return response()->json(['data' => ['credential_id' => $credential->identifier()], 'code' => 'totp_verified', 'message' => 'TOTP was verified.']);
    }

    /**
     * Revoke one TOTP credential.
     */
    public function revoke(
        Request $request,
        TotpCredential $credential,
        RevokeTotpCredentialAction $action,
    ): JsonResponse {
        $action->execute($this->subject($request), $credential);

        return response()->json(['data' => null, 'code' => 'totp_revoked', 'message' => 'The TOTP credential was revoked.']);
    }
}
