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
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Http\Requests\StorePermissionRequest;
use Nvl\Auth\ValueObjects\PermissionData;

/** Handles package-owned permission catalog transport. */
final class PermissionController extends AuthenticatedController
{
    /** List permissions. */
    public function index(Request $request, ListPermissionsAction $action): JsonResponse
    {
        $request->validate([
            'search' => ['sometimes', 'string', 'max:160'],
            'group' => ['sometimes', 'string', 'max:120'],
            'per_page' => ['sometimes', 'integer', 'between:1,100'],
        ]);

        return response()->json([
            'data' => $action->execute(
                $this->subject($request),
                $this->optionalStringInput($request, 'search'),
                $this->optionalStringInput($request, 'group'),
                (int) $request->integer('per_page', 25),
            ),
            'code' => 'permissions_listed',
            'message' => 'Permissions were listed.',
        ]);
    }

    /** Create a permission. */
    public function store(StorePermissionRequest $request, CreatePermissionAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $this->data($request)),
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
    public function update(StorePermissionRequest $request, string $permission, UpdatePermissionAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request), $permission, $this->data($request)), 'code' => 'permission_updated', 'message' => 'The permission was updated.']);
    }

    /** Delete one permission. */
    public function destroy(Request $request, string $permission, DeletePermissionAction $action): JsonResponse
    {
        $action->execute($this->subject($request), $permission);

        return response()->json(['data' => null, 'code' => 'permission_deleted', 'message' => 'The permission was deleted.']);
    }

    /** Build permission input from validated transport data. */
    private function data(StorePermissionRequest $request): PermissionData
    {
        return new PermissionData(
            name: $this->stringInput($request, 'name'),
            displayName: $this->optionalStringInput($request, 'display_name'),
            description: $this->optionalStringInput($request, 'description'),
            group: $this->optionalStringInput($request, 'group'),
            system: false,
            metadata: $this->associativeInput($request, 'metadata'),
        );
    }
}
