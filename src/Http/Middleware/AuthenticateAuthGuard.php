<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Middleware;

use Closure;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Http\Request;
use LogicException;
use Nvl\Auth\Services\AuthConfiguration;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates package routes through the explicitly configured Auth guard.
 */
final readonly class AuthenticateAuthGuard
{
    /** Create the configured-guard middleware. */
    public function __construct(
        private Authenticate $authenticate,
        private AuthConfiguration $configuration,
    ) {}

    /**
     * Authenticate the request without falling back to Laravel's default guard.
     *
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $this->authenticate->handle(
            $request,
            $next,
            $this->configuration->string('guard', 'web'),
        );

        if (! $response instanceof Response) {
            throw new LogicException('Auth guard middleware must receive an HTTP response.');
        }

        return $response;
    }
}
