<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\DeletePermissionAction;
use Nvl\Auth\Actions\Rbac\ListPermissionsAction;
use Nvl\Auth\Actions\Rbac\ShowPermissionAction;
use Nvl\Auth\Actions\Rbac\UpdatePermissionAction;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Data\Mutations\UpdatePermissionData;
use Nvl\Auth\Data\Queries\PermissionIndexQueryData;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;

/** Handles package-owned permission catalog transport. */
final class PermissionController extends AuthenticatedController
{
    /** List permissions. */
    public function index(Request $request, ListPermissionsAction $action): JsonResponse
    {
        $query = PermissionIndexQueryData::validateAndCreate($request->all());

        return response()->json([
            'data' => $action->execute(
                $this->subject($request),
                $query->search,
                $query->group,
                $query->perPage ?? 25,
            ),
            'code' => 'permissions_listed',
            'message' => 'Permissions were listed.',
        ]);
    }

    /** Create a permission. */
    public function store(StorePermissionData $data, Request $request, CreatePermissionAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $data),
            'code' => 'permission_created',
            'message' => 'The permission was created.',
        ], 201);
    }

    /** Show one permission. */
    public function show(Request $request, string $permission, ShowPermissionAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request), $permission), 'code' => 'permission_shown', 'message' => 'The permission was shown.']);
    }

    /** Update one permission. */
    public function update(Request $request, string $permission, UpdatePermissionAction $action): JsonResponse
    {
        $data = UpdatePermissionData::validateForUpdate($this->requestPayload($request), $permission);

        return response()->json(['data' => $action->execute($this->subject($request), $permission, $data), 'code' => 'permission_updated', 'message' => 'The permission was updated.']);
    }

    /** Delete one permission. */
    public function destroy(Request $request, string $permission, DeletePermissionAction $action): JsonResponse
    {
        $action->execute($this->subject($request), $permission);

        return response()->json(['data' => null, 'code' => 'permission_deleted', 'message' => 'The permission was deleted.']);
    }
}
