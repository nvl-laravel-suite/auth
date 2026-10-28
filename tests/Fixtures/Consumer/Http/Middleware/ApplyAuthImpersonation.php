<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Nvl\Auth\Adapters\Laravel\LaravelImpersonation;
use Symfony\Component\HttpFoundation\Response;

/** Host places this after managed admission and before business authorization; start/stop endpoints stay outside the overlay. */
final readonly class ApplyAuthImpersonation
{
    public function __construct(private LaravelImpersonation $impersonation, private AuthManager $auth) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $name = config('nvl-auth.guard', 'web');
        $id = $request->session()->get('nvl-auth.impersonation.'.$name);
        if (! is_string($id)) {
            return $next($request);
        }

        return $this->impersonation->run($this->auth->guard($name), $request->session(), $name, $id, fn (): Response => $next($request));
    }
}
