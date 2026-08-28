<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Nvl\Auth\Actions\Rbac\ApplyRoleTemplateAction;
use Nvl\Auth\Actions\Rbac\CloneRoleAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\ListRoleHierarchyAction;
use Nvl\Auth\Actions\Rbac\ListRoleTemplatesAction;
use Nvl\Auth\Actions\Rbac\ShowRbacAnalyticsAction;
use Nvl\Auth\Data\Display\PermissionGroupData;
use Nvl\Auth\Data\Display\PermissionListItemData;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Data\Display\RoleAnalyticsData;
use Nvl\Auth\Data\Display\RoleListItemData;
use Nvl\Auth\Data\Display\RoleNameAvailabilityData;
use Nvl\Auth\Data\Display\RoleOptionData;
use Nvl\Auth\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

it('owns role and permission CRUD foundations, cloning, hierarchy, templates, and analytics', function (): void {
    $actor = $this->user('rbac.owner@example.test');
    app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('catalog.read', group: 'catalog'));
    app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('catalog.write', group: 'catalog'));
    $parent = app(CreateRoleAction::class)->execute($actor, new StoreRoleData(
        name: 'catalog-manager',
        priority: 100,
        permissions: ['catalog.read', 'catalog.write'],
    ));
    $child = app(CreateRoleAction::class)->execute($actor, new StoreRoleData(
        name: 'catalog-reader',
        parentId: $parent->id,
        priority: 50,
        permissions: ['catalog.read'],
    ));
    $clone = app(CloneRoleAction::class)->execute($actor, $child, 'catalog-observer');
    $actor->assignRole($parent);
    $templates = app(ListRoleTemplatesAction::class)->execute($actor);
    $template = app(ApplyRoleTemplateAction::class)->execute($actor, new ApplyRoleTemplateData('auth-auditor'));
    $hierarchy = app(ListRoleHierarchyAction::class)->execute($actor);
    $parentNode = collect($hierarchy)->firstWhere('id', $parent->id);
    $childNode = collect($parentNode['children'] ?? [])->firstWhere('id', $child->id);
    $analytics = app(ShowRbacAnalyticsAction::class)->execute($actor);

    expect($clone->hasPermissionTo('catalog.read'))->toBeTrue()
        ->and($clone->is_system)->toBeFalse()
        ->and(collect($templates)->pluck('key')->all())->toBe(['auth-auditor', 'auth-user-manager', 'super-admin'])
        ->and($template->is_system)->toBeTrue()
        ->and($template->hasPermissionTo('nvl-auth.audits.view'))->toBeTrue()
        ->and($parentNode)->toBeArray()
        ->and($childNode)->toBeArray()
        ->and($analytics->roles)->toBe(4)
        ->and($analytics->permissions)->toBeGreaterThanOrEqual(4)
        ->and($analytics->roleAssignments)->toBe(1);
});

it('serializes role and permission options from package models', function (): void {
    $role = Role::factory()->create([
        'name' => 'editor',
        'display_name' => 'Editor',
        'description' => 'Edits content',
        'is_system' => false,
    ]);
    $permission = Permission::factory()->create([
        'name' => 'content.publish',
        'display_name' => '   ',
        'description' => 'Publishes content',
        'group' => '   ',
    ]);

    expect(RoleOptionData::fromModel($role)->toArray())->toMatchArray([
        'id' => $role->id,
        'name' => 'editor',
        'label' => 'Editor',
        'description' => 'Edits content',
        'isSystem' => false,
    ])->and(PermissionOptionData::fromModel($permission)->toArray())->toMatchArray([
        'id' => $permission->id,
        'name' => 'content.publish',
        'label' => 'content.publish',
        'description' => 'Publishes content',
        'group' => 'general',
    ]);
});

it('serializes stable role and permission catalog projections', function (): void {
    $createdAt = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $role = new RoleListItemData(
        id: 'role-id',
        name: 'editor',
        label: '',
        description: null,
        guard: 'web',
        isSystem: false,
        priority: 20,
        parentId: 'parent-id',
        parentName: 'manager',
        permissionIds: ['permission-a'],
        permissionsCount: 1,
        usersCount: 2,
        createdAt: $createdAt,
    );
    $permission = new PermissionListItemData(
        id: 'permission-id',
        name: 'content.publish',
        label: '',
        description: null,
        guard: 'web',
        group: '',
        roleIds: ['role-id'],
        rolesCount: 1,
        usersCount: 3,
        createdAt: $createdAt,
    );

    expect($role->toArray())->toMatchArray([
        'id' => 'role-id',
        'label' => 'editor',
        'parentId' => 'parent-id',
        'permissionIds' => ['permission-a'],
        'permissionsCount' => 1,
        'usersCount' => 2,
    ])->and($permission->toArray())->toMatchArray([
        'id' => 'permission-id',
        'label' => 'content.publish',
        'group' => 'general',
        'roleIds' => ['role-id'],
        'rolesCount' => 1,
        'usersCount' => 3,
    ]);
});

it('normalizes permission groups and role analytics deterministically', function (): void {
    $group = new PermissionGroupData('', '', 4);
    $availability = new RoleNameAvailabilityData('editor', false, 'role-id');
    $analytics = new RoleAnalyticsData(
        roleId: 'role-id',
        users: 5,
        activeUsers: 3,
        inactiveUsers: 2,
        permissions: 6,
        children: 2,
        descendants: 4,
        parentName: 'manager',
        permissionGroups: [
            'zeta' => 2,
            'alpha' => 3,
            'beta' => 2,
        ],
    );

    expect($group->toArray())->toBe([
        'value' => 'general',
        'label' => 'general',
        'permissionsCount' => 4,
    ])->and($availability->toArray())->toBe([
        'name' => 'editor',
        'available' => false,
        'conflictingRoleId' => 'role-id',
    ])->and($analytics->toArray())->toMatchArray([
        'roleId' => 'role-id',
        'users' => 5,
        'activeUsers' => 3,
        'inactiveUsers' => 2,
        'permissions' => 6,
        'children' => 2,
        'descendants' => 4,
        'parentName' => 'manager',
        'permissionGroups' => [
            'alpha' => 3,
            'beta' => 2,
            'zeta' => 2,
        ],
    ])->and(array_keys($analytics->permissionGroups))->toBe(['alpha', 'beta', 'zeta']);
});
