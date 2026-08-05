<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Data\Mutations\LoginData;
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
    public function login(LoginData $data, LoginAction $action): JsonResponse
    {
        $subject = $action->execute($data);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return response()->json([
            'data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]],
            'code' => 'authenticated',
            'message' => 'Authentication succeeded.',
        ]);
    }
}
