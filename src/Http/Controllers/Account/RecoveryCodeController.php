<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\RecoveryCodes\ConsumeRecoveryCodeAction;
use Nvl\Auth\Actions\RecoveryCodes\RegenerateRecoveryCodesAction;
use Nvl\Auth\Actions\RecoveryCodes\RevokeRecoveryCodesAction;
use Nvl\Auth\Data\Mutations\ConsumeRecoveryCodeData;

/**
 * Handles authenticated recovery-code lifecycle transport.
 */
final class RecoveryCodeController extends AuthenticatedController
{
    /**
     * Replace all recovery codes and return plaintext values once.
     */
    public function regenerate(Request $request, RegenerateRecoveryCodesAction $action): JsonResponse
    {
        $result = $action->execute($this->subject($request));

        return response()->json([
            'data' => ['batch_id' => $result->batchId, 'codes' => $result->codes],
            'code' => 'recovery_codes_regenerated',
            'message' => 'Recovery codes were regenerated.',
        ], 201);
    }

    /**
     * Consume one recovery code.
     */
    public function consume(ConsumeRecoveryCodeData $data, Request $request, ConsumeRecoveryCodeAction $action): JsonResponse
    {
        $record = $action->execute($this->subject($request), $data);

        return response()->json(['data' => ['batch_id' => $record->batch_id], 'code' => 'recovery_code_consumed', 'message' => 'The recovery code was consumed.']);
    }

    /**
     * Revoke all unused recovery codes.
     */
    public function revoke(Request $request, RevokeRecoveryCodesAction $action): JsonResponse
    {
        $count = $action->execute($this->subject($request));

        return response()->json(['data' => ['count' => $count], 'code' => 'recovery_codes_revoked', 'message' => 'Recovery codes were revoked.']);
    }
}
