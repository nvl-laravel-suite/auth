<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRbacReader;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\PermissionListItemData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StorePermissionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdatePermissionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\PermissionIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;

/** Handles package-owned permission catalog transport. */
final class PermissionController extends AuthenticatedController
{
    /** List permissions. */
    public function index(Request $request, AuthRbacReader $action): JsonResponse
    {
        $query = array_replace(['search' => null, 'group' => null, 'per_page' => null, 'guard' => null, 'sort' => null, 'direction' => null, 'includeAssignments' => false], Validator::make(AuthRequestInput::aliased($request->all(), ['per_page' => ['perPage'], 'includeAssignments' => ['include_assignments']]), PermissionIndexQueryData::rules())->validate());
        if (isset($query['per_page'])) {
            $query['per_page'] = (int) $query['per_page'];
        }
        if (isset($query['includeAssignments'])) {
            $query['includeAssignments'] = (bool) $query['includeAssignments'];
        }

        return response()->json([
            'data' => $action->permissions(
                $this->subject($request),
                $query['search'],
                $query['group'],
                $query['per_page'] ?? 25,
            )->through(PermissionListItemData::fromModel(...)),
            'code' => 'permissions_listed', 'message' => trans('nvl-auth::responsecode.permissions_listed'),
        ]);
    }

    /** Create a permission. */
    public function store(Request $request, AuthPermissions $action): JsonResponse
    {
        $data = array_replace(['displayName' => null, 'description' => null, 'group' => null, 'system' => false, 'metadata' => []], Validator::make(AuthRequestInput::aliased($request->all(), ['displayName' => ['display_name']]), StorePermissionData::rules())->validate());
        if (isset($data['system'])) {
            $data['system'] = (bool) $data['system'];
        }

        return response()->json([
            'data' => $action->create($this->subject($request), $data),
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
        if (isset($data['system'])) {
            $data['system'] = (bool) $data['system'];
        }

        return response()->json(['data' => $action->update($this->subject($request), $permission, $data), 'code' => 'permission_updated', 'message' => trans('nvl-auth::responsecode.permission_updated')]);
    }

    /** Delete one permission. */
    public function destroy(Request $request, string $permission, AuthPermissions $action): JsonResponse
    {
        $action->delete($this->subject($request), $permission);

        return response()->json(['data' => null, 'code' => 'permission_deleted', 'message' => trans('nvl-auth::responsecode.permission_deleted')]);
    }
}
