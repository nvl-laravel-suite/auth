<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rechecks feature admission for stale route-cache safety.
 */
final readonly class EnsureAuthFeatureAvailable
{
    /**
     * Create the route feature gate.
     */
    public function __construct(private FeatureGate $features) {}

    /**
     * Require the configured feature operation.
     *
     * @param  Closure(Request): Response  $next
     */
    public function handle(
        Request $request,
        Closure $next,
        string $feature,
        string $operation = 'read',
    ): Response {
        $resolvedFeature = AuthFeature::tryFrom($feature);
        $resolvedOperation = FeatureOperation::tryFrom($operation);

        if (! $resolvedFeature instanceof AuthFeature || ! $resolvedOperation instanceof FeatureOperation) {
            throw AuthException::invalidConfiguration('An Auth route declares an invalid feature operation.');
        }

        try {
            $this->features->assertAllowed($resolvedFeature, $resolvedOperation);
        } catch (AuthException $exception) {
            return new JsonResponse([
                'data' => null,
                'code' => $exception->errorCode,
                'message' => $exception->getMessage(),
            ], $exception->status);
        }

        return $next($request);
    }
}
