<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Passwords\ResetPasswordAction;
use Nvl\Auth\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;

/**
 * Handles password reset HTTP requests without sending notifications.
 */
final class PasswordController
{
    use InteractsWithValidatedInput;

    /**
     * Create a password broker token and emit a delivery request.
     */
    public function requestReset(
        RequestPasswordResetData $data,
        Request $request,
        RequestPasswordResetAction $action,
        Timebox $timebox,
    ): JsonResponse {
        $timebox->dontReturnEarly()->call(static function () use ($action, $data, $request): void {
            $action->execute($data, $request->getPreferredLanguage());
        }, 200_000);

        return response()->json([
            'data' => null,
            'code' => 'password_reset_requested', 'message' => trans('nvl-auth::responsecode.password_reset_requested'),
        ], 202);
    }

    /**
     * Consume a password broker token.
     */
    public function reset(ResetPasswordData $data, ResetPasswordAction $action): JsonResponse
    {
        $action->execute($data);

        return response()->json([
            'data' => null,
            'code' => 'password_reset', 'message' => trans('nvl-auth::responsecode.password_reset'),
        ]);
    }
}
