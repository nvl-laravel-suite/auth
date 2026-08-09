<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

/**
 * Enforces the package principal activation and lock policy at login time.
 */
final class PrincipalEligibility
{
    /**
     * Require one authenticated subject to remain eligible.
     */
    public function assertAuthenticationAllowed(Authenticatable $subject): void
    {
        if ($subject instanceof User && ! $subject->isAuthenticationAllowed()) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
    }
}
