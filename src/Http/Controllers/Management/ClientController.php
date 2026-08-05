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
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\ValueObjects\AuthClientData;

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
    public function store(Request $request, CreateAuthClientAction $action): JsonResponse
    {
        $client = $action->execute($this->subject($request), $this->data($request));

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
        Request $request,
        AuthClient $client,
        UpdateAuthClientAction $action,
    ): JsonResponse {
        $updated = $action->execute($this->subject($request), $client, $this->data($request));

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
        $request->validate(['active' => ['required', 'boolean']]);
        $client = $action->execute($this->subject($request), $client, $request->boolean('active'));

        return response()->json([
            'data' => $client,
            'code' => $client->is_active ? 'client_activated' : 'client_deactivated',
            'message' => $client->is_active ? 'The Auth client was activated.' : 'The Auth client was deactivated.',
        ]);
    }

    /**
     * Validate and create Auth client input.
     */
    private function data(Request $request): AuthClientData
    {
        $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'surface' => ['required', 'string', 'max:40'],
            'base_url' => ['required', 'url', 'max:2048'],
            'return_paths' => ['sometimes', 'array'],
            'return_paths.*' => ['string', 'max:2048'],
            'allowed_origins' => ['sometimes', 'array'],
            'allowed_origins.*' => ['url', 'max:2048'],
            'allowed_flows' => ['sometimes', 'array'],
            'allowed_flows.*' => ['string', 'max:80'],
            'metadata' => ['sometimes', 'array'],
            'active' => ['sometimes', 'boolean'],
        ]);

        return new AuthClientData(
            name: $this->stringInput($request, 'name'),
            surface: $this->stringInput($request, 'surface'),
            baseUrl: $this->stringInput($request, 'base_url'),
            returnPaths: $this->stringListInput($request, 'return_paths'),
            allowedOrigins: $this->stringListInput($request, 'allowed_origins'),
            allowedFlows: $this->stringListInput($request, 'allowed_flows', ['login']),
            metadata: $this->associativeInput($request, 'metadata'),
            active: $request->missing('active') || $request->boolean('active'),
        );
    }
}
