<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthEmailVerification;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ConfirmPasswordData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdatePasswordData;
use Spatie\LaravelData\Optional;

/**
 * Handles authenticated account credential operations.
 */
final class AuthenticationController extends AuthenticatedController
{
    /**
     * Log out through the configured Laravel guard.
     */
    public function logout(Request $request, AuthenticationSessions $action): JsonResponse
    {
        $action->logout(auth()->guard(config('nvl-auth.guard', 'web')), $request->session());

        return response()->json(['data' => null, 'code' => 'logged_out', 'message' => trans('nvl-auth::responsecode.logged_out')]);
    }

    /**
     * Change the current subject's password.
     */
    public function updatePassword(
        UpdatePasswordData $data,
        Request $request,
        AuthPasswords $action,
    ): JsonResponse {
        $subject = $this->subject($request);

        if (! $subject instanceof CanResetPassword) {
            throw AuthException::invalidConfiguration('The host subject does not support password updates.');
        }

        $action->update($subject, array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional), grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json(['data' => null, 'code' => 'password_updated', 'message' => trans('nvl-auth::responsecode.password_updated')]);
    }

    /** Issue a native operation grant independently of Laravel's presentation timestamp. */
    public function reauthenticate(Request $request, AuthReauthentication $service): JsonResponse
    {
        $input = $request->validate(['purpose' => ['required', Rule::enum(RecentAuthenticationPurpose::class)], 'proof' => ['required', 'array']]);
        $grant = $service->confirm($this->subject($request), $input['proof'], RecentAuthenticationPurpose::from($input['purpose']), $this->authenticationContext($request));

        return response()->json(['data' => ['grant' => $grant->reveal(), 'expires_in' => 300]]);
    }

    /**
     * Confirm the current password in Laravel's browser session.
     */
    public function confirmPassword(ConfirmPasswordData $data, Request $request, AuthPasswords $action): JsonResponse
    {
        $action->confirm($this->subject($request), array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional), $request->session());

        return response()->json([
            'data' => null,
            'code' => 'password_confirmed', 'message' => trans('nvl-auth::responsecode.password_confirmed'),
        ]);
    }

    /**
     * Emit an email-verification delivery request.
     */
    public function requestEmailVerification(
        Request $request,
        AuthEmailVerification $action,
    ): JsonResponse {
        $subject = $this->subject($request);

        if (! $subject instanceof MustVerifyEmail) {
            throw AuthException::invalidConfiguration('The host subject does not support email verification.');
        }

        $action->request($subject, $request->getPreferredLanguage());

        return response()->json(['data' => null, 'code' => 'email_verification_requested', 'message' => trans('nvl-auth::responsecode.email_verification_requested')], 202);
    }
}
