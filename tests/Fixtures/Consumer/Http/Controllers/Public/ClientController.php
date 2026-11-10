<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\AuthClients;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StartClientAuthData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;

/**
 * Handles hosted first-party client start requests.
 */
final class ClientController
{
    use InteractsWithValidatedInput;

    /**
     * Resolve an allowlisted client return URL.
     */
    public function start(Request $request, AuthClients $action): JsonResponse
    {
        $data = array_replace(['origin' => null], Validator::make(AuthRequestInput::aliased($request->all(), ['clientId' => ['client_id'], 'returnPath' => ['return_path']]), StartClientAuthData::rules())->validate());

        $result = $action->start($data);

        return response()->json([
            'data' => ['client_id' => $result['client']->identifier(), 'flow' => $result['flow'], 'return_url' => $result['returnUrl']],
            'code' => 'client_started', 'message' => trans('nvl-auth::responsecode.client_started'),
        ]);
    }
}
