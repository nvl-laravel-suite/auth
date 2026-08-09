<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Handles public password authentication transport concerns.
 */
final class AuthenticationController
{
    use InteractsWithValidatedInput;

    /**
     * Authenticate one browser user.
     */
    public function login(LoginData $data, Request $request, LoginAction $action): JsonResponse
    {
        $subject = $action->execute($data, new AuthenticationRequestContext(
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            requestId: $request->headers->get('X-Request-ID'),
        ));
        $reference = SubjectReference::fromAuthenticatable($subject);

        return response()->json([
            'data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]],
            'code' => 'authenticated',
            'message' => 'Authentication succeeded.',
        ]);
    }
}
