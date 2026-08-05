<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;

/**
 * Resolves the account surface's authenticated host subject.
 */
abstract class AuthenticatedController
{
    use InteractsWithValidatedInput;

    /**
     * Require an authenticated request subject.
     */
    protected function subject(Request $request): Authenticatable
    {
        $subject = $request->user();

        if (! $subject instanceof Authenticatable) {
            throw new AuthException('unauthenticated', 'Authentication is required.', 401);
        }

        return $subject;
    }
}
