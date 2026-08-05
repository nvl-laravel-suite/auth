<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;
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
    public function login(Request $request, LoginAction $action): JsonResponse
    {
        $request->validate([
            'identifier' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:4096'],
            'remember' => ['sometimes', 'boolean'],
        ]);
        $subject = $action->execute(
            $this->stringInput($request, 'identifier'),
            $this->stringInput($request, 'password'),
            $request->boolean('remember'),
        );
        $reference = SubjectReference::fromAuthenticatable($subject);

        return response()->json([
            'data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]],
            'code' => 'authenticated',
            'message' => 'Authentication succeeded.',
        ]);
    }
}
