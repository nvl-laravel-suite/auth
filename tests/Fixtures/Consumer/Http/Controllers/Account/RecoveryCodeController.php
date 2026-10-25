<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ConsumeRecoveryCodeData;
use Spatie\LaravelData\Optional;

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
        $result = $action->regenerateRecoveryCodes($this->subject($request));

        return response()->json([
            'data' => ['batch_id' => $result->batchId, 'codes' => $result->codes],
            'code' => 'recovery_codes_regenerated', 'message' => trans('nvl-auth::responsecode.recovery_codes_regenerated'),
        ], 201);
    }

    /**
     * Consume one recovery code.
     */
    public function consume(ConsumeRecoveryCodeData $data, Request $request, AuthSecondFactor $action): JsonResponse
    {
        $record = $action->consumeRecoveryCode($this->subject($request), array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));

        return response()->json(['data' => ['batch_id' => $record->batch_id], 'code' => 'recovery_code_consumed', 'message' => trans('nvl-auth::responsecode.recovery_code_consumed')]);
    }

    /**
     * Revoke all unused recovery codes.
     */
    public function revoke(Request $request, AuthSecondFactor $action): JsonResponse
    {
        $count = $action->revokeRecoveryCodes($this->subject($request));

        return response()->json(['data' => ['count' => $count], 'code' => 'recovery_codes_revoked', 'message' => trans('nvl-auth::responsecode.recovery_codes_revoked')]);
    }
}
