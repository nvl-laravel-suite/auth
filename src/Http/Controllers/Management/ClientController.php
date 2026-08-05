<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Clients\CreateAuthClientAction;
use Nvl\Auth\Actions\Clients\DeleteAuthClientAction;
use Nvl\Auth\Actions\Clients\ListAuthClientsAction;
use Nvl\Auth\Actions\Clients\SetAuthClientActiveAction;
use Nvl\Auth\Actions\Clients\ShowAuthClientAction;
use Nvl\Auth\Actions\Clients\UpdateAuthClientAction;
use Nvl\Auth\Data\Mutations\StoreClientData;
use Nvl\Auth\Data\Mutations\UpdateClientData;
use Nvl\Auth\Data\Mutations\UpdateClientStatusData;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Models\AuthClient;

/**
 * Handles authorized first-party Auth client management transport.
 */
final class ClientController extends AuthenticatedController
{
    /**
     * List Auth clients.
     */
    public function index(Request $request, ListAuthClientsAction $action): JsonResponse
    {
        $page = $action->execute($this->subject($request), (int) $request->integer('per_page', 25));

        return response()->json(['data' => $page, 'code' => 'clients_listed', 'message' => 'Auth clients were listed.']);
    }

    /**
     * Create an Auth client.
     */
    public function store(StoreClientData $data, Request $request, CreateAuthClientAction $action): JsonResponse
    {
        $client = $action->execute($this->subject($request), $data);

        return response()->json(['data' => $client, 'code' => 'client_created', 'message' => 'The Auth client was created.'], 201);
    }

    /**
     * Show one Auth client.
     */
    public function show(
        Request $request,
        AuthClient $client,
        ShowAuthClientAction $action,
    ): JsonResponse {
        $client = $action->execute($this->subject($request), $client);

        return response()->json(['data' => $client, 'code' => 'client_shown', 'message' => 'The Auth client was shown.']);
    }

    /**
     * Update an Auth client.
     */
    public function update(
        UpdateClientData $data,
        Request $request,
        AuthClient $client,
        UpdateAuthClientAction $action,
    ): JsonResponse {
        $updated = $action->execute($this->subject($request), $client, $data);

        return response()->json(['data' => $updated, 'code' => 'client_updated', 'message' => 'The Auth client was updated.']);
    }

    /**
     * Delete an Auth client.
     */
    public function destroy(
        Request $request,
        AuthClient $client,
        DeleteAuthClientAction $action,
    ): JsonResponse {
        $action->execute($this->subject($request), $client);

        return response()->json(['data' => null, 'code' => 'client_deleted', 'message' => 'The Auth client was deleted.']);
    }

    /**
     * Activate or deactivate one Auth client.
     */
    public function status(
        Request $request,
        AuthClient $client,
        SetAuthClientActiveAction $action,
    ): JsonResponse {
        $data = UpdateClientStatusData::validateAndCreate($request->all());
        $client = $action->execute($this->subject($request), $client, $data->active);

        return response()->json([
            'data' => $client,
            'code' => $client->is_active ? 'client_activated' : 'client_deactivated',
            'message' => $client->is_active ? 'The Auth client was activated.' : 'The Auth client was deactivated.',
        ]);
    }
}
