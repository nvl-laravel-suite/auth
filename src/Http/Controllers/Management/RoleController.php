<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Rbac\ApplyRoleTemplateAction;
use Nvl\Auth\Actions\Rbac\CloneRoleAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\DeleteRoleAction;
use Nvl\Auth\Actions\Rbac\ListRoleHierarchyAction;
use Nvl\Auth\Actions\Rbac\ListRolesAction;
use Nvl\Auth\Actions\Rbac\ListRoleTemplatesAction;
use Nvl\Auth\Actions\Rbac\ShowRbacAnalyticsAction;
use Nvl\Auth\Actions\Rbac\ShowRoleAction;
use Nvl\Auth\Actions\Rbac\UpdateRoleAction;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Http\Requests\ApplyRoleTemplateRequest;
use Nvl\Auth\Http\Requests\CloneRoleRequest;
use Nvl\Auth\Http\Requests\StoreRoleRequest;
use Nvl\Auth\ValueObjects\RoleData;

/** Handles package-owned role, hierarchy, template, and analytics transport. */
final class RoleController extends AuthenticatedController
{
    /** List roles. */
    public function index(Request $request, ListRolesAction $action): JsonResponse
    {
        $request->validate(['search' => ['sometimes', 'string', 'max:160'], 'per_page' => ['sometimes', 'integer', 'between:1,100']]);

        return response()->json([
            'data' => $action->execute($this->subject($request), $this->optionalStringInput($request, 'search'), (int) $request->integer('per_page', 25)),
            'code' => 'roles_listed',
            'message' => 'Roles were listed.',
        ]);
    }

    /** Show the nested role hierarchy. */
    public function hierarchy(Request $request, ListRoleHierarchyAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request)), 'code' => 'role_hierarchy_shown', 'message' => 'The role hierarchy was shown.']);
    }

    /** Show contributed role templates. */
    public function templates(Request $request, ListRoleTemplatesAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request)), 'code' => 'role_templates_listed', 'message' => 'Role templates were listed.']);
    }

    /** Show RBAC analytics. */
    public function analytics(Request $request, ShowRbacAnalyticsAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request)), 'code' => 'rbac_analytics_shown', 'message' => 'RBAC analytics were shown.']);
    }

    /** Create a role. */
    public function store(StoreRoleRequest $request, CreateRoleAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $this->data($request)),
            'code' => 'role_created',
            'message' => 'The role was created.',
        ], 201);
    }

    /** Show one role. */
    public function show(Request $request, string $role, ShowRoleAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request), $role), 'code' => 'role_shown', 'message' => 'The role was shown.']);
    }

    /** Update one role. */
    public function update(StoreRoleRequest $request, string $role, UpdateRoleAction $action): JsonResponse
    {
        return response()->json(['data' => $action->execute($this->subject($request), $role, $this->data($request)), 'code' => 'role_updated', 'message' => 'The role was updated.']);
    }

    /** Clone one role. */
    public function clone(CloneRoleRequest $request, string $role, CloneRoleAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute(
                $this->subject($request),
                $role,
                $this->stringInput($request, 'name'),
                $this->optionalStringInput($request, 'display_name'),
            ),
            'code' => 'role_cloned',
            'message' => 'The role was cloned.',
        ], 201);
    }

    /** Apply one canonical role template. */
    public function applyTemplate(ApplyRoleTemplateRequest $request, ApplyRoleTemplateAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $this->stringInput($request, 'template')),
            'code' => 'role_template_applied',
            'message' => 'The role template was applied.',
        ]);
    }

    /** Delete one role. */
    public function destroy(Request $request, string $role, DeleteRoleAction $action): JsonResponse
    {
        $action->execute($this->subject($request), $role);

        return response()->json(['data' => null, 'code' => 'role_deleted', 'message' => 'The role was deleted.']);
    }

    /** Build role input from validated transport data. */
    private function data(StoreRoleRequest $request): RoleData
    {
        return new RoleData(
            name: $this->stringInput($request, 'name'),
            displayName: $this->optionalStringInput($request, 'display_name'),
            description: $this->optionalStringInput($request, 'description'),
            parentId: $this->optionalStringInput($request, 'parent_id'),
            priority: (int) $request->integer('priority', 0),
            system: false,
            permissions: $this->stringListInput($request, 'permissions'),
            metadata: $this->associativeInput($request, 'metadata'),
        );
    }
}
