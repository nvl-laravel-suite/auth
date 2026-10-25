<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ConfirmTotpEnrollmentData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\VerifyTotpData;
use Spatie\LaravelData\Optional;

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
    public function start(StartTotpEnrollmentData $data, Request $request, AuthSecondFactor $action): JsonResponse
    {
        $result = $action->startEnrollment(
            $this->subject($request),
            array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional),
        );

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
        ConfirmTotpEnrollmentData $data,
        Request $request,
        TotpCredential $credential,
        AuthSecondFactor $action,
    ): JsonResponse {
        $confirmed = $action->confirmEnrollment(
            $this->subject($request),
            $credential,
            array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional),
        );

        return response()->json(['data' => ['credential_id' => $confirmed->identifier()], 'code' => 'totp_enrolled', 'message' => trans('nvl-auth::responsecode.totp_enrolled')]);
    }

    /**
     * Verify a current TOTP proof.
     */
    public function verify(VerifyTotpData $data, Request $request, AuthSecondFactor $action): JsonResponse
    {
        $credential = $action->verify($this->subject($request), array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));

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
        $action->revoke($this->subject($request), $credential);

        return response()->json(['data' => null, 'code' => 'totp_revoked', 'message' => trans('nvl-auth::responsecode.totp_revoked')]);
    }
}
