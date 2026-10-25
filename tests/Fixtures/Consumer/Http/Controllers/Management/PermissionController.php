<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRbacReader;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\PermissionListItemData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StorePermissionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdatePermissionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\PermissionIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;
use Spatie\LaravelData\Optional;

/** Handles package-owned permission catalog transport. */
final class PermissionController extends AuthenticatedController
{
    /** List permissions. */
    public function index(Request $request, AuthRbacReader $action): JsonResponse
    {
        $query = PermissionIndexQueryData::validateAndCreate($request->all());

        return response()->json([
            'data' => $action->permissions(
                $this->subject($request),
                $query->search,
                $query->group,
                $query->perPage ?? 25,
            )->through(PermissionListItemData::fromModel(...)),
            'code' => 'permissions_listed', 'message' => trans('nvl-auth::responsecode.permissions_listed'),
        ]);
    }

    /** Create a permission. */
    public function store(StorePermissionData $data, Request $request, AuthPermissions $action): JsonResponse
    {
        return response()->json([
            'data' => $action->create($this->subject($request), array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional)),
            'code' => 'permission_created', 'message' => trans('nvl-auth::responsecode.permission_created'),
        ], 201);
    }

    /** Show one permission. */
    public function show(Request $request, string $permission, AuthRbacReader $action): JsonResponse
    {
        return response()->json(['data' => $action->permission($this->subject($request), $permission), 'code' => 'permission_shown', 'message' => trans('nvl-auth::responsecode.permission_shown')]);
    }

    /** Update one permission. */
    public function update(Request $request, string $permission, AuthPermissions $action): JsonResponse
    {
        $data = UpdatePermissionData::validateForUpdate($this->requestPayload($request), $permission);

        return response()->json(['data' => $action->update($this->subject($request), $permission, array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional)), 'code' => 'permission_updated', 'message' => trans('nvl-auth::responsecode.permission_updated')]);
    }

    /** Delete one permission. */
    public function destroy(Request $request, string $permission, AuthPermissions $action): JsonResponse
    {
        $action->delete($this->subject($request), $permission);

        return response()->json(['data' => null, 'code' => 'permission_deleted', 'message' => trans('nvl-auth::responsecode.permission_deleted')]);
    }
}
