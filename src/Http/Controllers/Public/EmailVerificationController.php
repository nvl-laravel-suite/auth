<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\VerifyEmailAction;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Handles signed public email verification links.
 */
final class EmailVerificationController
{
    /**
     * Resolve the host subject and mark its email verified.
     */
    public function verify(
        Request $request,
        string $id,
        string $hash,
        AuthSubjectResolver $subjects,
        VerifyEmailAction $action,
    ): JsonResponse {
        $type = $request->query('subject_type');

        if (! is_string($type) || trim($type) === '') {
            throw new AuthException('verification_invalid', 'The email verification link is invalid.', 403);
        }

        $subject = $subjects->resolve(new SubjectReference($type, $id));

        if (! $subject instanceof MustVerifyEmail
            || ! hash_equals(sha1($subject->getEmailForVerification()), $hash)) {
            throw new AuthException('verification_invalid', 'The email verification link is invalid.', 403);
        }

        $changed = $action->execute($subject);

        return response()->json([
            'data' => ['changed' => $changed],
            'code' => 'email_verified',
            'message' => 'The email address was verified.',
        ]);
    }
}
