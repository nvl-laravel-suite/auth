<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Clients\StartAuthClientAction;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;

/**
 * Handles hosted first-party client start requests.
 */
final class ClientController
{
    use InteractsWithValidatedInput;

    /**
     * Resolve an allowlisted client return URL.
     */
    public function start(Request $request, StartAuthClientAction $action): JsonResponse
    {
        $request->validate([
            'client_id' => ['required', 'uuid'],
            'flow' => ['required', 'string', 'max:80'],
            'return_path' => ['required', 'string', 'max:2048'],
            'origin' => ['sometimes', 'nullable', 'url', 'max:2048'],
        ]);
        $result = $action->execute(
            $this->stringInput($request, 'client_id'),
            $this->stringInput($request, 'flow'),
            $this->stringInput($request, 'return_path'),
            $this->optionalStringInput($request, 'origin'),
        );

        return response()->json([
            'data' => ['client_id' => $result->client->identifier(), 'flow' => $result->flow, 'return_url' => $result->returnUrl],
            'code' => 'client_started',
            'message' => 'The client authentication flow may start.',
        ]);
    }
}
