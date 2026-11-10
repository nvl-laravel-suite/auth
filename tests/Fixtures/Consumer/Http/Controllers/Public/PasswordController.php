<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Timebox;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;

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
        AuthPasswords $action,
        Timebox $timebox,
    ): JsonResponse {
        $data = Validator::make($request->all(), RequestPasswordResetData::rules())->validate();

        $timebox->dontReturnEarly()->call(static function () use ($action, $data, $request): void {
            $action->requestReset($data, $request->getPreferredLanguage());
        }, 200_000);

        return response()->json([
            'data' => null,
            'code' => 'password_reset_requested', 'message' => trans('nvl-auth::responsecode.password_reset_requested'),
        ], 202);
    }

    /**
     * Consume a password broker token.
     */
    public function reset(Request $request, AuthPasswords $action): JsonResponse
    {
        $data = Validator::make(AuthRequestInput::aliased($request->all(), ['passwordConfirmation' => ['password_confirmation']]), ResetPasswordData::rules())->validate();

        $action->reset($data);

        return response()->json([
            'data' => null,
            'code' => 'password_reset', 'message' => trans('nvl-auth::responsecode.password_reset'),
        ]);
    }
}
