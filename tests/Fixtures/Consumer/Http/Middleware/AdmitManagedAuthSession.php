<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Nvl\Auth\Adapters\Laravel\LaravelSessionAdmission;
use Symfony\Component\HttpFoundation\Response;

/** Consumer-owned placement after Laravel auth and before application authorization. */
final readonly class AdmitManagedAuthSession
{
    public function __construct(private LaravelSessionAdmission $admission, private AuthManager $auth) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        if (config('nvl-auth.features.managed_sessions.enabled') === true) {
            $name = config('nvl-auth.guard', 'web');
            $this->admission->admit($this->auth->guard($name), $request->session(), $name);
        }

        return $next($request);
    }
}
