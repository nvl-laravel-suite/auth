<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Totp\ConfirmTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\RevokeTotpCredentialAction;
use Nvl\Auth\Actions\Totp\StartTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\VerifyTotpAction;
use Nvl\Auth\Data\Mutations\ConfirmTotpEnrollmentData;
use Nvl\Auth\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Data\Mutations\VerifyTotpData;
use Nvl\Auth\Models\TotpCredential;

/**
 * Handles authenticated TOTP enrollment and lifecycle transport.
 */
final class TotpController extends AuthenticatedController
{
    /**
     * Start TOTP enrollment.
     */
    public function start(StartTotpEnrollmentData $data, Request $request, StartTotpEnrollmentAction $action): JsonResponse
    {
        $result = $action->execute(
            $this->subject($request),
            $data,
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
        ConfirmTotpEnrollmentData $data,
        Request $request,
        TotpCredential $credential,
        ConfirmTotpEnrollmentAction $action,
    ): JsonResponse {
        $confirmed = $action->execute(
            $this->subject($request),
            $credential,
            $data,
        );

        return response()->json(['data' => ['credential_id' => $confirmed->identifier()], 'code' => 'totp_enrolled', 'message' => 'TOTP was enrolled.']);
    }

    /**
     * Verify a current TOTP proof.
     */
    public function verify(VerifyTotpData $data, Request $request, VerifyTotpAction $action): JsonResponse
    {
        $credential = $action->execute($this->subject($request), $data);

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
