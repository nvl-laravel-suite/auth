<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthOwnerAdmission;
use Nvl\Auth\Services\AuthOwnershipState;
use Nvl\Support\Ownership\Exceptions\OwnershipException;
use Symfony\Component\HttpFoundation\Response;

/** Revalidates the authenticated principal inside an explicitly admitted native owner scope. @api */
final readonly class EnsureAuthOwnerAccess
{
    /** Retain the authenticated guard and fresh owner admission policy. */
    public function __construct(private Factory $auth, private AuthOwnerAdmission $admission, private AuthOwnershipState $state) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $subject = $this->auth->guard()->user();
            if (! $this->state->configured() || ! $subject instanceof Authenticatable) {
                abort(404, 'Owner was not found.');
            }
            $this->admission->assertAllowed($subject);
        } catch (OwnershipException|AuthException) {
            abort(404, 'Owner was not found.');
        }

        return $next($request);
    }
}
