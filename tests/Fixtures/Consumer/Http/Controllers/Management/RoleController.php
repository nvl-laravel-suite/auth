<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\AuthRbacReader;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\RoleListItemData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\CloneRoleData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StoreRoleData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateRoleData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\RoleIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;

/** Handles package-owned role, hierarchy, template, and analytics transport. */
final class RoleController extends AuthenticatedController
{
    /** List roles. */
    public function index(Request $request, AuthRbacReader $action): JsonResponse
    {
        $query = array_replace(['search' => null, 'per_page' => null, 'isSystem' => null, 'guard' => null, 'sort' => null, 'direction' => null, 'includeAssignments' => false], Validator::make(AuthRequestInput::aliased($request->all(), ['per_page' => ['perPage'], 'isSystem' => ['is_system'], 'includeAssignments' => ['include_assignments']]), RoleIndexQueryData::rules())->validate());
        if (isset($query['per_page'])) {
            $query['per_page'] = (int) $query['per_page'];
        }
        if (isset($query['isSystem'])) {
            $query['isSystem'] = (bool) $query['isSystem'];
        }
        if (isset($query['includeAssignments'])) {
            $query['includeAssignments'] = (bool) $query['includeAssignments'];
        }

        return response()->json([
            'data' => $action->roles($this->subject($request), $query['search'], $query['per_page'] ?? 25)->through(RoleListItemData::fromModel(...)),
            'code' => 'roles_listed', 'message' => trans('nvl-auth::responsecode.roles_listed'),
        ]);
    }

    /** Show the nested role hierarchy. */
    public function hierarchy(Request $request, AuthRbacReader $action): JsonResponse
    {
        return response()->json(['data' => $action->roleHierarchy($this->subject($request)), 'code' => 'role_hierarchy_shown', 'message' => trans('nvl-auth::responsecode.role_hierarchy_shown')]);
    }

    /** Show contributed role templates. */
    public function templates(Request $request, AuthRbacReader $action): JsonResponse
    {
        return response()->json(['data' => $action->roleTemplates($this->subject($request)), 'code' => 'role_templates_listed', 'message' => trans('nvl-auth::responsecode.role_templates_listed')]);
    }

    /** Show RBAC analytics. */
    public function analytics(Request $request, AuthRbacReader $action): JsonResponse
    {
        return response()->json(['data' => $action->analytics($this->subject($request)), 'code' => 'rbac_analytics_shown', 'message' => trans('nvl-auth::responsecode.rbac_analytics_shown')]);
    }

    /** Create a role. */
    public function store(Request $request, AuthRoles $action): JsonResponse
    {
        $data = array_replace(['displayName' => null, 'description' => null, 'parentId' => null, 'priority' => 0, 'system' => false, 'permissions' => [], 'metadata' => []], Validator::make(AuthRequestInput::aliased($request->all(), ['displayName' => ['display_name'], 'parentId' => ['parent_id']]), StoreRoleData::rules())->validate());
        if (isset($data['priority'])) {
            $data['priority'] = (int) $data['priority'];
        }
        if (isset($data['system'])) {
            $data['system'] = (bool) $data['system'];
        }

        return response()->json([
            'data' => $action->create($this->subject($request), $data),
            'code' => 'role_created', 'message' => trans('nvl-auth::responsecode.role_created'),
        ], 201);
    }

    /** Show one role. */
    public function show(Request $request, string $role, AuthRbacReader $action): JsonResponse
    {
        return response()->json(['data' => $action->role($this->subject($request), $role), 'code' => 'role_shown', 'message' => trans('nvl-auth::responsecode.role_shown')]);
    }

    /** Update one role. */
    public function update(Request $request, string $role, AuthRoles $action): JsonResponse
    {
        $data = UpdateRoleData::validateForUpdate($this->requestPayload($request), $role);
        if (isset($data['priority'])) {
            $data['priority'] = (int) $data['priority'];
        }
        if (isset($data['system'])) {
            $data['system'] = (bool) $data['system'];
        }

        return response()->json(['data' => $action->update($this->subject($request), $role, $data), 'code' => 'role_updated', 'message' => trans('nvl-auth::responsecode.role_updated')]);
    }

    /** Clone one role. */
    public function clone(Request $request, string $role, AuthRoles $action): JsonResponse
    {
        $data = array_replace(['display_name' => null], Validator::make(AuthRequestInput::aliased($request->all(), ['display_name' => ['displayName']]), CloneRoleData::rules())->validate());

        return response()->json([
            'data' => $action->duplicate(
                $this->subject($request),
                $role,
                $data['name'],
                $data['display_name'],
            ),
            'code' => 'role_cloned', 'message' => trans('nvl-auth::responsecode.role_cloned'),
        ], 201);
    }

    /** Apply one canonical role template. */
    public function applyTemplate(Request $request, AuthRoles $action): JsonResponse
    {
        $data = array_replace(['roleName' => null], Validator::make(AuthRequestInput::aliased($request->all(), ['roleName' => ['role_name']]), ApplyRoleTemplateData::rules())->validate());

        return response()->json([
            'data' => $action->applyTemplate($this->subject($request), $data),
            'code' => 'role_template_applied', 'message' => trans('nvl-auth::responsecode.role_template_applied'),
        ]);
    }

    /** Delete one role. */
    public function destroy(Request $request, string $role, AuthRoles $action): JsonResponse
    {
        $action->delete($this->subject($request), $role);

        return response()->json(['data' => null, 'code' => 'role_deleted', 'message' => trans('nvl-auth::responsecode.role_deleted')]);
    }
}
