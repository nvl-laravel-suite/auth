<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Nvl\Auth\Actions\Clients\StartAuthClientAction;
use Nvl\Auth\Data\Mutations\StartClientAuthData;
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
    public function start(StartClientAuthData $data, StartAuthClientAction $action): JsonResponse
    {
        $result = $action->execute($data);

        return response()->json([
            'data' => ['client_id' => $result->client->identifier(), 'flow' => $result->flow, 'return_url' => $result->returnUrl],
            'code' => 'client_started',
            'message' => 'The client authentication flow may start.',
        ]);
    }
}
