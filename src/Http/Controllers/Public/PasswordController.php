<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Passwords\ResetPasswordAction;
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
        Request $request,
        RequestPasswordResetAction $action,
    ): JsonResponse {
        $request->validate(['identifier' => ['required', 'string', 'max:255']]);
        $action->execute($this->stringInput($request, 'identifier'), $request->getPreferredLanguage());

        return response()->json([
            'data' => null,
            'code' => 'password_reset_requested',
            'message' => 'If the account is eligible, password reset instructions were requested.',
        ], 202);
    }

    /**
     * Consume a password broker token.
     */
    public function reset(Request $request, ResetPasswordAction $action): JsonResponse
    {
        $request->validate([
            'identifier' => ['required', 'string', 'max:255'],
            'token' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed'],
        ]);
        $action->execute(
            $this->stringInput($request, 'identifier'),
            $this->stringInput($request, 'token'),
            $this->stringInput($request, 'password'),
        );

        return response()->json([
            'data' => null,
            'code' => 'password_reset',
            'message' => 'The password was reset.',
        ]);
    }
}
