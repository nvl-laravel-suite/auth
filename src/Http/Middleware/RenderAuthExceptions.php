<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response as LaravelResponse;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Http\PackageExceptionPayload;
use Symfony\Component\HttpFoundation\Response;

/**
 * Renders stable JSON envelopes only for package routes.
 */
final readonly class RenderAuthExceptions
{
    public function __construct(private PackageExceptionPayload $payload) {}

    /**
     * Render package failures without taking over the host exception handler.
     *
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $response = $next($request);
        } catch (AuthException $exception) {
            return $this->response($exception);
        }
        if (($response instanceof JsonResponse || $response instanceof LaravelResponse)
            && $response->exception instanceof AuthException) {
            return $this->response($response->exception);
        }

        return $response;
    }

    /** Preserve the native Auth envelope and established status. */
    private function response(AuthException $exception): JsonResponse
    {
        $payload = $this->payload->for($exception);

        return new JsonResponse([
            'data' => null,
            'code' => $payload['code'],
            'message' => $payload['message'],
        ], $exception->status, $this->payload->headers($exception));
    }
}
