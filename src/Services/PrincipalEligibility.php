<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

/**
 * Enforces the package principal activation and lock policy at login time.
 */
final class PrincipalEligibility implements AuthenticationEligibility
{
    /**
     * Require one authenticated subject to remain eligible.
     */
    public function assertEligible(Authenticatable $subject, AuthenticationPurpose $purpose): void
    {
        if ($subject instanceof User && ! $subject->isAuthenticationAllowed()) {
            if ($purpose === AuthenticationPurpose::CredentialLogin) {
                throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
            }

            throw new AuthException(
                'subject_ineligible',
                'Authentication cannot be completed.',
                422,
            );
        }
    }
}
