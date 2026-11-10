<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ConsumeRecoveryCodeData;

/**
 * Handles authenticated recovery-code lifecycle transport.
 */
final class RecoveryCodeController extends AuthenticatedController
{
    /**
     * Replace all recovery codes and return plaintext values once.
     */
    public function regenerate(Request $request, AuthSecondFactor $action): JsonResponse
    {
        $result = $action->regenerateRecoveryCodes($this->subject($request), grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json([
            'data' => ['batch_id' => $result->batchId, 'codes' => $result->codes],
            'code' => 'recovery_codes_regenerated', 'message' => trans('nvl-auth::responsecode.recovery_codes_regenerated'),
        ], 201);
    }

    /**
     * Consume one recovery code.
     */
    public function consume(Request $request, AuthSecondFactor $action): JsonResponse
    {
        $data = Validator::make($request->all(), ConsumeRecoveryCodeData::rules())->validate();

        $record = $action->consumeRecoveryCode($this->subject($request), $data);

        return response()->json(['data' => ['batch_id' => $record->batch_id], 'code' => 'recovery_code_consumed', 'message' => trans('nvl-auth::responsecode.recovery_code_consumed')]);
    }

    /**
     * Revoke all unused recovery codes.
     */
    public function revoke(Request $request, AuthSecondFactor $action): JsonResponse
    {
        $count = $action->revokeRecoveryCodes($this->subject($request), grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json(['data' => ['count' => $count], 'code' => 'recovery_codes_revoked', 'message' => trans('nvl-auth::responsecode.recovery_codes_revoked')]);
    }
}
