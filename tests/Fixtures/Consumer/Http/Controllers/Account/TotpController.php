<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ConfirmTotpEnrollmentData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\VerifyTotpData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;

/**
 * Handles authenticated TOTP enrollment and lifecycle transport.
 */
final class TotpController extends AuthenticatedController
{
    /** Return secret-free state for the authenticated principal without restarting enrollment. */
    public function show(Request $request, AuthSecondFactor $action): JsonResponse
    {
        return response()->json([
            'data' => $action->state($this->subject($request)),
            'code' => 'totp_security_state_shown',
            'message' => trans('nvl-auth::responsecode.totp_security_state_shown'),
        ]);
    }

    /**
     * Start TOTP enrollment.
     */
    public function start(Request $request, AuthSecondFactor $action): JsonResponse
    {
        $data = array_replace(['name' => null], Validator::make(AuthRequestInput::aliased($request->all(), ['accountName' => ['account_name']]), StartTotpEnrollmentData::rules())->validate());

        $result = $action->startEnrollment($this->subject($request), $data, grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json([
            'data' => [
                'credential_id' => $result->credential->identifier(),
                'secret' => $result->secret,
                'provisioning_uri' => $result->provisioningUri,
            ],
            'code' => 'totp_enrollment_started', 'message' => trans('nvl-auth::responsecode.totp_enrollment_started'),
        ], 201);
    }

    /**
     * Confirm TOTP enrollment.
     */
    public function confirm(
        Request $request,
        TotpCredential $credential,
        AuthSecondFactor $action,
    ): JsonResponse {
        $data = Validator::make($request->all(), ConfirmTotpEnrollmentData::rules())->validate();

        $confirmed = $action->confirmEnrollment($this->subject($request), $credential, $data, grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json(['data' => ['credential_id' => $confirmed->identifier()], 'code' => 'totp_enrolled', 'message' => trans('nvl-auth::responsecode.totp_enrolled')]);
    }

    /**
     * Verify a current TOTP proof.
     */
    public function verify(Request $request, AuthSecondFactor $action): JsonResponse
    {
        $data = Validator::make($request->all(), VerifyTotpData::rules())->validate();

        $credential = $action->verify($this->subject($request), $data);

        return response()->json(['data' => ['credential_id' => $credential->identifier()], 'code' => 'totp_verified', 'message' => trans('nvl-auth::responsecode.totp_verified')]);
    }

    /**
     * Revoke one TOTP credential.
     */
    public function revoke(
        Request $request,
        TotpCredential $credential,
        AuthSecondFactor $action,
    ): JsonResponse {
        $action->revoke($this->subject($request), $credential, grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json(['data' => null, 'code' => 'totp_revoked', 'message' => trans('nvl-auth::responsecode.totp_revoked')]);
    }
}
