<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\LogoutAction;
use Nvl\Auth\Actions\Authentication\RequestEmailVerificationAction;
use Nvl\Auth\Actions\Passwords\ConfirmPasswordAction;
use Nvl\Auth\Actions\Passwords\UpdatePasswordAction;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Handles authenticated account credential operations.
 */
final class AuthenticationController extends AuthenticatedController
{
    /**
     * Log out through the configured Laravel guard.
     */
    public function logout(LogoutAction $action): JsonResponse
    {
        $action->execute();

        return response()->json(['data' => null, 'code' => 'logged_out', 'message' => 'The session was ended.']);
    }

    /**
     * Change the current subject's password.
     */
    public function updatePassword(Request $request, UpdatePasswordAction $action): JsonResponse
    {
        $request->validate([
            'current_password' => ['required', 'string', 'max:4096'],
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed'],
        ]);
        $subject = $this->subject($request);

        if (! $subject instanceof CanResetPassword) {
            throw AuthException::invalidConfiguration('The host subject does not support password updates.');
        }

        $action->execute(
            $subject,
            $this->stringInput($request, 'current_password'),
            $this->stringInput($request, 'password'),
        );

        return response()->json(['data' => null, 'code' => 'password_updated', 'message' => 'The password was updated.']);
    }

    /**
     * Confirm the current password in Laravel's browser session.
     */
    public function confirmPassword(Request $request, ConfirmPasswordAction $action): JsonResponse
    {
        $request->validate(['password' => ['required', 'string', 'max:4096']]);
        $action->execute($this->subject($request), $this->stringInput($request, 'password'));

        return response()->json([
            'data' => null,
            'code' => 'password_confirmed',
            'message' => 'The password was confirmed.',
        ]);
    }

    /**
     * Emit an email-verification delivery request.
     */
    public function requestEmailVerification(
        Request $request,
        RequestEmailVerificationAction $action,
    ): JsonResponse {
        $subject = $this->subject($request);

        if (! $subject instanceof MustVerifyEmail) {
            throw AuthException::invalidConfiguration('The host subject does not support email verification.');
        }

        $action->execute($subject, $request->getPreferredLanguage());

        return response()->json(['data' => null, 'code' => 'email_verification_requested', 'message' => 'Email verification was requested.'], 202);
    }
}
