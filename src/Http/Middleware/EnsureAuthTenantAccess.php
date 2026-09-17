<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthTenantAdmission;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\Exceptions\TenantInactive;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/** Verifies Auth membership and token ownership before foundation context entry. */
final readonly class EnsureAuthTenantAccess
{
    public function __construct(
        private TenantHttpResolver $resolver,
        private Factory $auth,
        private AuthTenantAdmission $admission,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $tenant = $this->resolver->resolve($request);
            $subject = $this->auth->guard()->user();
            if (! $subject instanceof Authenticatable) {
                throw new TenantBoundaryViolation;
            }
            $this->admission->assertAllowed($subject, $tenant);

            return $next($request);
        } catch (TenantBoundaryViolation|TenantInactive|TenantNotFound|AuthException $exception) {
            throw new NotFoundHttpException('Tenant was not found.', $exception);
        }
    }
}
