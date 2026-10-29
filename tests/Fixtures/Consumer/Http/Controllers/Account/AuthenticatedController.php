<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/**
 * Resolves the account surface's authenticated host subject.
 */
abstract class AuthenticatedController
{
    use InteractsWithValidatedInput;

    protected function recentGrant(Request $request): string
    {
        $grant = $request->header('X-Recent-Authentication');

        return is_string($grant) ? $grant : '';
    }

    protected function authenticationContext(Request $request): AuthenticationRequestContext
    {
        if (! $request->hasSession()) {
            throw new AuthException('authentication_binding_invalid', 'A trusted browser session is required.', 422);
        }
        $guard = config('nvl-auth.authorization.guard', 'web');
        $key = AuthBrowserSessions::bindingKey($guard);

        return new AuthenticationRequestContext(guardName: $guard, sessionBinding: $request->session()->getId(), browserSessionId: $request->session()->get($key.'-id'), browserBinding: $request->session()->get($key));
    }

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
