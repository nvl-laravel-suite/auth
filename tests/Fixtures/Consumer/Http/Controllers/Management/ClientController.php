<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Services\AuthClients;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StoreClientData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateClientData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateClientStatusData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;

/**
 * Handles authorized first-party Auth client management transport.
 */
final class ClientController extends AuthenticatedController
{
    /**
     * List Auth clients.
     */
    public function index(Request $request, AuthClients $action): JsonResponse
    {
        $page = $action->paginate($this->subject($request), (int) $request->integer('per_page', 25));

        return response()->json(['data' => $page, 'code' => 'clients_listed', 'message' => trans('nvl-auth::responsecode.clients_listed')]);
    }

    /**
     * Create an Auth client.
     */
    public function store(Request $request, AuthClients $action): JsonResponse
    {
        $data = array_replace(['returnPaths' => [], 'allowedOrigins' => [], 'allowedFlows' => ['login'], 'metadata' => [], 'active' => true], Validator::make(AuthRequestInput::aliased($request->all(), ['baseUrl' => ['base_url'], 'returnPaths' => ['return_paths'], 'allowedOrigins' => ['allowed_origins'], 'allowedFlows' => ['allowed_flows']]), StoreClientData::rules())->validate());
        if (isset($data['active'])) {
            $data['active'] = (bool) $data['active'];
        }

        $client = $action->create($this->subject($request), $data);

        return response()->json(['data' => $client, 'code' => 'client_created', 'message' => trans('nvl-auth::responsecode.client_created')], 201);
    }

    /**
     * Show one Auth client.
     */
    public function show(
        Request $request,
        AuthClient $client,
        AuthClients $action,
    ): JsonResponse {
        $client = $action->find($this->subject($request), $client);

        return response()->json(['data' => $client, 'code' => 'client_shown', 'message' => trans('nvl-auth::responsecode.client_shown')]);
    }

    /**
     * Update an Auth client.
     */
    public function update(
        Request $request,
        AuthClient $client,
        AuthClients $action,
    ): JsonResponse {
        $data = array_replace(['returnPaths' => [], 'allowedOrigins' => [], 'allowedFlows' => ['login'], 'metadata' => [], 'active' => true], Validator::make(AuthRequestInput::aliased($request->all(), ['baseUrl' => ['base_url'], 'returnPaths' => ['return_paths'], 'allowedOrigins' => ['allowed_origins'], 'allowedFlows' => ['allowed_flows']]), UpdateClientData::rules())->validate());
        if (isset($data['active'])) {
            $data['active'] = (bool) $data['active'];
        }

        $updated = $action->update($this->subject($request), $client, $data);

        return response()->json(['data' => $updated, 'code' => 'client_updated', 'message' => trans('nvl-auth::responsecode.client_updated')]);
    }

    /**
     * Delete an Auth client.
     */
    public function destroy(
        Request $request,
        AuthClient $client,
        AuthClients $action,
    ): JsonResponse {
        $action->delete($this->subject($request), $client);

        return response()->json(['data' => null, 'code' => 'client_deleted', 'message' => trans('nvl-auth::responsecode.client_deleted')]);
    }

    /**
     * Activate or deactivate one Auth client.
     */
    public function status(
        Request $request,
        AuthClient $client,
        AuthClients $action,
    ): JsonResponse {
        $data = Validator::make($request->all(), UpdateClientStatusData::rules())->validate();
        if (isset($data['active'])) {
            $data['active'] = (bool) $data['active'];
        }

        $client = $action->setActive($this->subject($request), $client, $data['active']);

        return response()->json([
            'data' => $client,
            'code' => $client->is_active ? 'client_activated' : 'client_deactivated',
            'message' => $client->is_active ? trans('nvl-auth::responsecode.client_activated') : trans('nvl-auth::responsecode.client_deactivated'),
        ]);
    }
}
