<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Nvl\Auth\Services\AuthClients;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StartClientAuthData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Spatie\LaravelData\Optional;

/**
 * Handles hosted first-party client start requests.
 */
final class ClientController
{
    use InteractsWithValidatedInput;

    /**
     * Resolve an allowlisted client return URL.
     */
    public function start(StartClientAuthData $data, AuthClients $action): JsonResponse
    {
        $result = $action->start(array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));

        return response()->json([
            'data' => ['client_id' => $result['client']->identifier(), 'flow' => $result['flow'], 'return_url' => $result['returnUrl']],
            'code' => 'client_started', 'message' => trans('nvl-auth::responsecode.client_started'),
        ]);
    }
}
