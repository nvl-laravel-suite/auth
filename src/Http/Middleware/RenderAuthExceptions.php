<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Renders stable JSON envelopes only for package routes.
 */
final class RenderAuthExceptions
{
    /**
     * Render package failures without taking over the host exception handler.
     *
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            return $next($request);
        } catch (AuthException $exception) {
            return new JsonResponse([
                'data' => null,
                'code' => $exception->errorCode,
                'message' => $exception->getMessage(),
            ], $exception->status);
        }
    }
}
