<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Actions\Rbac\ApplyRoleTemplateAction;
use Nvl\Auth\Actions\Rbac\CloneRoleAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\ListPermissionCatalogAction;
use Nvl\Auth\Actions\Rbac\ListPermissionGroupsAction;
use Nvl\Auth\Actions\Rbac\ListPermissionOptionsAction;
use Nvl\Auth\Actions\Rbac\ListRoleCatalogAction;
use Nvl\Auth\Actions\Rbac\ListRoleHierarchyAction;
use Nvl\Auth\Actions\Rbac\ListRoleOptionsAction;
use Nvl\Auth\Actions\Rbac\ListRoleTemplatesAction;
use Nvl\Auth\Actions\Rbac\ShowRbacAnalyticsAction;
use Nvl\Auth\Actions\Rbac\SuggestPermissionsAction;
use Nvl\Auth\Actions\Rbac\SuggestRolesAction;
use Nvl\Auth\Contracts\AuthManagementAccess;
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
use Nvl\Auth\Data\Queries\PermissionIndexQueryData;
use Nvl\Auth\Data\Queries\RoleIndexQueryData;
use Nvl\Auth\Exceptions\AuthException;
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

it('returns bounded role and permission options through authorized DTO projections', function (): void {
    $actor = $this->user('rbac-options@example.test');
    Role::factory()->create([
        'name' => 'z-system',
        'display_name' => 'System Role',
        'description' => 'Built in role',
        'is_system' => true,
    ]);
    Role::factory()->create([
        'name' => 'editor',
        'display_name' => 'Friendly Editor',
        'description' => 'Edits published content',
    ]);
    Role::factory()->count(58)->create();
    Permission::factory()->create([
        'name' => 'content.publish',
        'display_name' => 'Publish Content',
        'description' => 'Publishes reviewed content',
        'group' => 'content',
    ]);
    Permission::factory()->create([
        'name' => 'users.manage',
        'display_name' => 'Manage Users',
        'description' => 'Administers people',
        'group' => 'identity',
    ]);

    $roles = app(ListRoleOptionsAction::class)->execute($actor, limit: 500);
    $roleSearch = app(SuggestRolesAction::class)->execute($actor, 'Friendly');
    $permissions = app(ListPermissionOptionsAction::class)->execute(
        $actor,
        search: 'reviewed',
        group: 'content',
        limit: 500,
    );

    expect($roles)->toHaveCount(50)
        ->and($roles->first())->toBeInstanceOf(RoleOptionData::class)
        ->and($roles->first()?->name)->toBe('z-system')
        ->and($roleSearch)->toHaveCount(1)
        ->and($roleSearch->first()?->name)->toBe('editor')
        ->and($permissions)->toHaveCount(1)
        ->and($permissions->first())->toBeInstanceOf(PermissionOptionData::class)
        ->and($permissions->first()?->group)->toBe('content')
        ->and(app(SuggestRolesAction::class)->execute($actor))->toHaveCount(50)
        ->and(app(SuggestPermissionsAction::class)->execute($actor))->toHaveCount(2)
        ->and(app(SuggestRolesAction::class)->execute($actor, 'a'))->toBeEmpty()
        ->and(app(SuggestPermissionsAction::class)->execute($actor, 'a'))->toBeEmpty();

    config()->set('nvl-auth.features.rbac.settings.role_option_limit', 2);
    config()->set('nvl-auth.features.rbac.settings.permission_option_limit', 1);

    expect(app(ListRoleOptionsAction::class)->execute($actor, limit: 50))->toHaveCount(2)
        ->and(app(ListPermissionOptionsAction::class)->execute($actor, limit: 50))->toHaveCount(1)
        ->and(fn () => app(SuggestRolesAction::class)->execute($actor, str_repeat('x', 161)))
        ->toThrow(AuthException::class, '160');
});

it('normalizes and counts permission groups in one authorized query', function (): void {
    $actor = $this->user('rbac-groups@example.test');
    Permission::factory()->create(['name' => 'general.null', 'group' => null]);
    Permission::factory()->create(['name' => 'general.blank', 'group' => '']);
    Permission::factory()->count(2)->create(['group' => 'content_management']);

    DB::flushQueryLog();
    DB::enableQueryLog();
    $groups = app(ListPermissionGroupsAction::class)->execute($actor);
    $queryCount = count(DB::getQueryLog());
    DB::disableQueryLog();

    expect($groups->map->toArray()->all())->toBe([
        [
            'value' => 'content_management',
            'label' => 'Content Management',
            'permissionsCount' => 2,
        ],
        [
            'value' => 'general',
            'label' => 'General',
            'permissionsCount' => 2,
        ],
    ])->and($queryCount)->toBe(1);
});

it('denies every RBAC consumer read before querying package storage', function (): void {
    $actor = $this->user('rbac-denied@example.test');
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return false;
        }
    });
    $reads = [
        static fn () => app(ListRoleOptionsAction::class)->execute($actor),
        static fn () => app(SuggestRolesAction::class)->execute($actor),
        static fn () => app(ListPermissionOptionsAction::class)->execute($actor),
        static fn () => app(SuggestPermissionsAction::class)->execute($actor),
        static fn () => app(ListPermissionGroupsAction::class)->execute($actor),
        static fn () => app(ListRoleCatalogAction::class)->execute($actor, new RoleIndexQueryData),
        static fn () => app(ListPermissionCatalogAction::class)->execute($actor, new PermissionIndexQueryData),
    ];

    foreach ($reads as $read) {
        DB::flushQueryLog();
        DB::enableQueryLog();

        expect($read)->toThrow(AuthException::class, 'not authorized')
            ->and(DB::getQueryLog())->toBe([]);

        DB::disableQueryLog();
    }
});

it('returns filtered stable DTO catalogs without related user identity data', function (): void {
    $actor = $this->user('rbac-catalog@example.test');
    $parent = Role::factory()->create(['name' => 'manager', 'display_name' => 'Manager']);
    $role = Role::factory()->create([
        'name' => 'editor',
        'display_name' => 'Content Editor',
        'description' => 'Edits content',
        'parent_id' => $parent->id,
        'priority' => 20,
    ]);
    $permission = Permission::factory()->create([
        'name' => 'content.publish',
        'display_name' => 'Publish Content',
        'group' => 'content',
    ]);
    $role->givePermissionTo($permission);
    $actor->assignRole($role);
    $actor->givePermissionTo($permission);

    $roles = app(ListRoleCatalogAction::class)->execute($actor, new RoleIndexQueryData(
        search: 'Editor',
        perPage: 500,
        isSystem: false,
        guard: 'web',
        sort: 'label',
        direction: 'asc',
        includeAssignments: true,
    ));
    $permissions = app(ListPermissionCatalogAction::class)->execute($actor, new PermissionIndexQueryData(
        search: 'Publish',
        group: 'content',
        perPage: 500,
        guard: 'web',
        sort: 'label',
        direction: 'asc',
        includeAssignments: true,
    ));
    $roleItem = $roles->items()[0] ?? null;
    $permissionItem = $permissions->items()[0] ?? null;

    expect($roles->perPage())->toBe(100)
        ->and($roleItem)->toBeInstanceOf(RoleListItemData::class)
        ->and($roleItem?->parentName)->toBe('manager')
        ->and($roleItem?->permissionIds)->toBe([$permission->id])
        ->and($roleItem?->permissionsCount)->toBe(1)
        ->and($roleItem?->usersCount)->toBe(1)
        ->and($permissions->perPage())->toBe(100)
        ->and($permissionItem)->toBeInstanceOf(PermissionListItemData::class)
        ->and($permissionItem?->roleIds)->toBe([$role->id])
        ->and($permissionItem?->rolesCount)->toBe(1)
        ->and($permissionItem?->usersCount)->toBe(1)
        ->and(array_keys($roleItem?->toArray() ?? []))->not->toContain('users', 'email')
        ->and(array_keys($permissionItem?->toArray() ?? []))->not->toContain('users', 'email');

    expect(fn () => new RoleIndexQueryData(sort: 'users'))
        ->toThrow(InvalidArgumentException::class, 'sort')
        ->and(fn () => new PermissionIndexQueryData(direction: 'sideways'))
        ->toThrow(InvalidArgumentException::class, 'direction');
});

it('keeps option and catalog query counts independent of fixture size', function (): void {
    $actor = $this->user('rbac-query-count@example.test');
    Role::factory()->create();
    Permission::factory()->create();

    $measure = function () use ($actor): array {
        $counts = [];

        foreach ([
            'roles' => static fn () => app(ListRoleOptionsAction::class)->execute($actor, limit: 50),
            'permissions' => static fn () => app(ListPermissionOptionsAction::class)->execute($actor, limit: 100),
            'role_catalog' => static fn () => app(ListRoleCatalogAction::class)->execute(
                $actor,
                new RoleIndexQueryData(perPage: 100),
            ),
            'permission_catalog' => static fn () => app(ListPermissionCatalogAction::class)->execute(
                $actor,
                new PermissionIndexQueryData(perPage: 100),
            ),
        ] as $name => $read) {
            DB::flushQueryLog();
            DB::enableQueryLog();
            $read();
            $counts[$name] = count(DB::getQueryLog());
            DB::disableQueryLog();
        }

        return $counts;
    };

    $singleCounts = $measure();
    Role::factory()->count(49)->create();
    Permission::factory()->count(99)->create();
    $populatedCounts = $measure();

    expect($singleCounts['roles'])->toBeLessThanOrEqual(1)
        ->and($singleCounts['permissions'])->toBeLessThanOrEqual(1)
        ->and($singleCounts['role_catalog'])->toBeLessThanOrEqual(3)
        ->and($singleCounts['permission_catalog'])->toBeLessThanOrEqual(2)
        ->and($populatedCounts)->toBe($singleCounts);
});
