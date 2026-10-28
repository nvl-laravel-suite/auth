<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\RegistrationRequest;

/** Consumer-selected neutral signup presentation; no package route is registered. */
final class RegistrationController
{
    public function __invoke(RegistrationRequest $request, AuthRegistration $registration): JsonResponse
    {
        try {
            $registration->register($request->validated());
        } catch (AuthException $exception) {
            if ($exception->errorCode !== 'registration_unavailable') {
                throw $exception;
            }
        }

        return response()->json(['message' => 'Your registration request was processed.'], 202);
    }
}
