<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRbacReader;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\PermissionGroupData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\PermissionListItemData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\PermissionOptionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\RoleAnalyticsData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\RoleListItemData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\RoleNameAvailabilityData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Display\RoleOptionData;
use Nvl\Auth\Tests\Fixtures\HostAnalyticsPrincipal;
use Nvl\Auth\Tests\Fixtures\HostRbacRole;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\SubjectReference;

it('owns role and permission CRUD foundations, cloning, hierarchy, templates, and analytics', function (): void {
    $actor = $this->user('rbac.owner@example.test');
    app(AuthPermissions::class)->create($actor, ['name' => 'catalog.read', 'group' => 'catalog']);
    app(AuthPermissions::class)->create($actor, ['name' => 'catalog.write', 'group' => 'catalog']);
    $parent = app(AuthRoles::class)->create($actor, ['name' => 'catalog-manager', 'priority' => 100, 'permissions' => ['catalog.read', 'catalog.write']]);
    $child = app(AuthRoles::class)->create($actor, ['name' => 'catalog-reader', 'parentId' => $parent->id, 'priority' => 50, 'permissions' => ['catalog.read']]);
    $clone = app(AuthRoles::class)->duplicate($actor, $child, 'catalog-observer');
    $actor->assignRole($parent);
    $templates = app(AuthRbacReader::class)->roleTemplates($actor);
    $template = app(AuthRoles::class)->applyTemplate($actor, ['template' => 'auth-auditor']);
    $hierarchy = app(AuthRbacReader::class)->roleHierarchy($actor);
    $parentNode = collect($hierarchy)->firstWhere('id', $parent->id);
    $childNode = collect($parentNode['children'] ?? [])->firstWhere('id', $child->id);
    $analytics = app(AuthRbacReader::class)->analytics($actor);

    expect($clone->hasPermissionTo('catalog.read'))->toBeTrue()
        ->and($clone->is_system)->toBeFalse()
        ->and(collect($templates)->pluck('key')->all())->toBe(['auth-auditor', 'auth-user-manager', 'super-admin'])
        ->and($template->is_system)->toBeTrue()
        ->and($template->hasPermissionTo('nvl.auth.audits.view'))->toBeTrue()
        ->and($parentNode)->toBeArray()
        ->and($childNode)->toBeArray()
        ->and($analytics['roles'])->toBe(4)
        ->and($analytics['permissions'])->toBeGreaterThanOrEqual(4)
        ->and($analytics['roleAssignments'])->toBe(1);
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

    $roles = app(AuthRbacReader::class)->roleOptions($actor, limit: 500)->map(RoleOptionData::fromModel(...));
    $roleSearch = app(AuthRbacReader::class)->suggestRoles($actor, 'Friendly')->map(RoleOptionData::fromModel(...));
    $permissions = app(AuthRbacReader::class)->permissionOptions(
        $actor,
        search: 'reviewed',
        group: 'content',
        limit: 500,
    )->map(PermissionOptionData::fromModel(...));

    expect($roles)->toHaveCount(50)
        ->and($roles->first())->toBeInstanceOf(RoleOptionData::class)
        ->and($roles->first()?->name)->toBe('z-system')
        ->and($roleSearch)->toHaveCount(1)
        ->and($roleSearch->first()?->name)->toBe('editor')
        ->and($permissions)->toHaveCount(1)
        ->and($permissions->first())->toBeInstanceOf(PermissionOptionData::class)
        ->and($permissions->first()?->group)->toBe('content')
        ->and(app(AuthRbacReader::class)->suggestRoles($actor)->map(RoleOptionData::fromModel(...)))->toHaveCount(50)
        ->and(app(AuthRbacReader::class)->suggestPermissions($actor)->map(PermissionOptionData::fromModel(...)))->toHaveCount(2)
        ->and(app(AuthRbacReader::class)->suggestRoles($actor, 'a')->map(RoleOptionData::fromModel(...)))->toBeEmpty()
        ->and(app(AuthRbacReader::class)->suggestPermissions($actor, 'a')->map(PermissionOptionData::fromModel(...)))->toBeEmpty();

    config()->set('nvl-auth.features.rbac.settings.role_option_limit', 2);
    config()->set('nvl-auth.features.rbac.settings.permission_option_limit', 1);

    expect(app(AuthRbacReader::class)->roleOptions($actor, limit: 50)->map(RoleOptionData::fromModel(...)))->toHaveCount(2)
        ->and(app(AuthRbacReader::class)->permissionOptions($actor, limit: 50)->map(PermissionOptionData::fromModel(...)))->toHaveCount(1)
        ->and(fn () => app(AuthRbacReader::class)->suggestRoles($actor, str_repeat('x', 161))->map(RoleOptionData::fromModel(...)))
        ->toThrow(AuthException::class, '160');
});

it('normalizes and counts permission groups in one authorized query', function (): void {
    $actor = $this->user('rbac-groups@example.test');
    Permission::factory()->create(['name' => 'general.null', 'group' => null]);
    Permission::factory()->create(['name' => 'general.blank', 'group' => '   ']);
    Permission::factory()->count(2)->create(['group' => 'content_management']);

    DB::flushQueryLog();
    DB::enableQueryLog();
    $groups = app(AuthRbacReader::class)->permissionGroups($actor)->map(static fn (array $row) => PermissionGroupData::from($row));
    $queries = authProtectedRbacReads(DB::getQueryLog());
    $queryCount = count($queries);
    DB::disableQueryLog();
    $groupQuery = str_replace(['`', '"', '[', ']'], '', mb_strtolower($queries[0]['query']));

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
    ])->and($queryCount)->toBe(1)
        ->and($groupQuery)->toContain('group by normalized_group');

    config()->set('nvl-auth.features.rbac.settings.permission_group_limit', 1);

    expect(app(AuthRbacReader::class)->permissionGroups($actor)->map(static fn (array $row) => PermissionGroupData::from($row)))
        ->toHaveCount(1)
        ->and(app(AuthRbacReader::class)->permissionGroups($actor)->map(static fn (array $row) => PermissionGroupData::from($row))->first()?->value)
        ->toBe('content_management');
});

it('filters whitespace-only permission groups through the canonical general group', function (): void {
    $actor = $this->user('rbac-general-group@example.test');
    $permission = Permission::factory()->create([
        'name' => 'general.whitespace',
        'group' => "\t \n",
    ]);
    $contentPermission = Permission::factory()->create([
        'name' => 'content.padded',
        'group' => "\t content \n",
    ]);
    $legacyControlPermission = Permission::factory()->create([
        'name' => 'legacy.control',
        'group' => "\flegacy\f",
    ]);

    $options = app(AuthRbacReader::class)->permissionOptions($actor, group: 'general')->map(PermissionOptionData::fromModel(...));
    $contentOptions = app(AuthRbacReader::class)->permissionOptions($actor, group: 'content')->map(PermissionOptionData::fromModel(...));
    $legacyControlOptions = app(AuthRbacReader::class)->permissionOptions($actor, group: "\flegacy\f")->map(PermissionOptionData::fromModel(...));
    $catalog = app(AuthRbacReader::class)->permissionCatalog(
        $actor,
        ['group' => 'content'],
    )->through(PermissionListItemData::fromModel(...));
    $groups = app(AuthRbacReader::class)->permissionGroups($actor)->map(static fn (array $row) => PermissionGroupData::from($row));
    $groupsByValue = $groups->keyBy('value');

    expect($options->pluck('id')->all())->toBe([$permission->id])
        ->and($options->first()?->group)->toBe('general')
        ->and($contentOptions->pluck('id')->all())->toBe([$contentPermission->id])
        ->and($contentOptions->first()?->group)->toBe('content')
        ->and($legacyControlOptions->pluck('id')->all())->toBe([$legacyControlPermission->id])
        ->and($legacyControlOptions->first()?->group)->toBe("\flegacy\f")
        ->and(collect($catalog->items())->pluck('id')->all())->toBe([$contentPermission->id])
        ->and($groupsByValue->get('content')?->permissionsCount)->toBe(1)
        ->and($groupsByValue->get('general')?->permissionsCount)->toBe(1)
        ->and($groupsByValue->get("\flegacy\f")?->permissionsCount)->toBe(1);
});

it('canonicalizes permission groups at package write boundaries', function (): void {
    $actor = $this->user('rbac-group-write@example.test');
    $permission = app(AuthPermissions::class)->create(
        $actor,
        ['name' => 'content.review', 'group' => "\t content \n"],
    );

    expect($permission->group)->toBe('content');

    $permission = app(AuthPermissions::class)->update(
        $actor,
        $permission,
        ['name' => 'content.review', 'group' => "\r editorial \v"],
    );

    expect($permission->group)->toBe('editorial');

    expect(fn () => app(AuthPermissions::class)->create($actor, ['name' => 'content.invalid', 'group' => "content\0legacy"]))
        ->toThrow(InvalidArgumentException::class, 'null bytes')
        ->and(fn () => app(AuthPermissions::class)->update($actor, $permission, ['name' => 'content.review', 'group' => "content\0legacy"]))
        ->toThrow(InvalidArgumentException::class, 'null bytes');
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
        static fn () => app(AuthRbacReader::class)->roleOptions($actor)->map(RoleOptionData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->suggestRoles($actor)->map(RoleOptionData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->permissionOptions($actor)->map(PermissionOptionData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->suggestPermissions($actor)->map(PermissionOptionData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->permissionGroups($actor)->map(static fn (array $row) => PermissionGroupData::from($row)),
        static fn () => app(AuthRbacReader::class)->roles($actor)->through(RoleListItemData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->permissions($actor)->through(PermissionListItemData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->roleCatalog($actor, [])->through(RoleListItemData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->permissionCatalog($actor, [])->through(PermissionListItemData::fromModel(...)),
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
    $secondPermission = Permission::factory()->create([
        'name' => 'content.archive',
        'display_name' => 'Archive Content',
        'group' => 'content',
    ]);
    $secondRole = Role::factory()->create(['name' => 'publisher']);
    $role->givePermissionTo($permission);
    $role->givePermissionTo($secondPermission);
    $secondRole->givePermissionTo($permission);
    $actor->assignRole($role);
    $actor->givePermissionTo($permission);

    $roles = app(AuthRbacReader::class)->roleCatalog($actor, ['search' => 'Editor', 'per_page' => 500, 'isSystem' => false, 'guard' => 'web', 'sort' => 'label', 'direction' => 'asc', 'includeAssignments' => true])->through(RoleListItemData::fromModel(...));
    $permissions = app(AuthRbacReader::class)->permissionCatalog($actor, ['search' => 'Publish', 'group' => 'content', 'per_page' => 500, 'guard' => 'web', 'sort' => 'label', 'direction' => 'asc', 'includeAssignments' => true])->through(PermissionListItemData::fromModel(...));
    $roleItem = $roles->items()[0] ?? null;
    $permissionItem = $permissions->items()[0] ?? null;

    expect($roles->perPage())->toBe(100)
        ->and($roleItem)->toBeInstanceOf(RoleListItemData::class)
        ->and($roleItem?->parentName)->toBe('manager')
        ->and($roleItem?->permissionIds)->toBe(collect([$permission->id, $secondPermission->id])->sort()->values()->all())
        ->and($roleItem?->permissionsCount)->toBe(2)
        ->and($roleItem?->usersCount)->toBe(1)
        ->and($permissions->perPage())->toBe(100)
        ->and($permissionItem)->toBeInstanceOf(PermissionListItemData::class)
        ->and($permissionItem?->roleIds)->toBe(collect([$role->id, $secondRole->id])->sort()->values()->all())
        ->and($permissionItem?->rolesCount)->toBe(2)
        ->and($permissionItem?->usersCount)->toBe(1)
        ->and(array_keys($roleItem?->toArray() ?? []))
        ->not->toContain('users')
        ->not->toContain('email')
        ->and(array_keys($permissionItem?->toArray() ?? []))
        ->not->toContain('users')
        ->not->toContain('email');

    expect(fn () => app(AuthRbacReader::class)->roleCatalog($actor, ['sort' => 'users']))
        ->toThrow(ValidationException::class, 'sort')
        ->and(fn () => app(AuthRbacReader::class)->roleCatalog($actor, ['direction' => 'sideways']))
        ->toThrow(ValidationException::class, 'direction');
});

it('returns compatibility role and permission pages as stable DTOs without mapping queries', function (): void {
    $actor = $this->user('rbac-compatibility-reads@example.test');
    $parent = Role::factory()->create([
        'name' => 'manager',
        'display_name' => 'Manager',
        'priority' => 10,
    ]);
    $role = Role::factory()->create([
        'name' => 'content-editor',
        'display_name' => 'Content Editor',
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

    DB::flushQueryLog();
    DB::enableQueryLog();

    try {
        $roles = app(AuthRbacReader::class)->roles(
            $actor,
            search: 'content',
            perPage: 1,
        )->through(RoleListItemData::fromModel(...));
        $roleQueryCount = count(DB::getQueryLog());
        $roleCatalogReads = count(array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'sqlite_master')));
        $roleItem = $roles->items()[0] ?? null;
        $roleItem?->toArray();

        expect(DB::getQueryLog())->toHaveCount($roleQueryCount)
            ->and($roleQueryCount - $roleCatalogReads)->toBeLessThanOrEqual(3)
            ->and($roleQueryCount - $roleCatalogReads)->toBeGreaterThan(0)
            ->and($roles->total())->toBe(1)
            ->and($roles->currentPage())->toBe(1)
            ->and($roles->perPage())->toBe(1)
            ->and($roles->getOptions()['path'] ?? null)->toBe($roles->path())
            ->and($roles->appends(['search' => 'content'])->url(2))->toContain(
                'page=2',
                'search=content',
            )
            ->and($roleItem)->toBeInstanceOf(RoleListItemData::class)
            ->and($roleItem?->name)->toBe('content-editor')
            ->and($roleItem?->label)->toBe('Content Editor')
            ->and($roleItem?->parentName)->toBe('manager')
            ->and($roleItem?->permissionsCount)->toBe(1)
            ->and($roleItem?->usersCount)->toBe(1);

        DB::flushQueryLog();
        $permissions = app(AuthRbacReader::class)->permissions(
            $actor,
            search: 'publish',
            group: 'content',
            perPage: 1,
        )->through(PermissionListItemData::fromModel(...));
        $permissionQueryCount = count(DB::getQueryLog());
        $permissionCatalogReads = count(array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'sqlite_master')));
        $permissionItem = $permissions->items()[0] ?? null;
        $permissionItem?->toArray();

        expect(DB::getQueryLog())->toHaveCount($permissionQueryCount)
            ->and($permissionQueryCount - $permissionCatalogReads)->toBeLessThanOrEqual(2)
            ->and($permissionCatalogReads)->toBeLessThanOrEqual(4)
            ->and($permissions->total())->toBe(1)
            ->and($permissions->currentPage())->toBe(1)
            ->and($permissions->perPage())->toBe(1)
            ->and($permissionItem)->toBeInstanceOf(PermissionListItemData::class)
            ->and($permissionItem?->name)->toBe('content.publish')
            ->and($permissionItem?->label)->toBe('Publish Content')
            ->and($permissionItem?->group)->toBe('content')
            ->and($permissionItem?->rolesCount)->toBe(1)
            ->and($permissionItem?->usersCount)->toBe(0);
    } finally {
        DB::disableQueryLog();
    }
});

it('keeps option and catalog query counts independent of fixture size', function (): void {
    $actor = $this->user('rbac-query-count@example.test');
    Role::factory()->create();
    Permission::factory()->create();

    $measure = function () use ($actor): array {
        $counts = [];

        foreach ([
            'roles' => static fn () => app(AuthRbacReader::class)->roleOptions($actor, limit: 50)->map(RoleOptionData::fromModel(...)),
            'permissions' => static fn () => app(AuthRbacReader::class)->permissionOptions($actor, limit: 100)->map(PermissionOptionData::fromModel(...)),
            'role_catalog' => static fn () => app(AuthRbacReader::class)->roleCatalog(
                $actor,
                ['per_page' => 100],
            )->through(RoleListItemData::fromModel(...)),
            'permission_catalog' => static fn () => app(AuthRbacReader::class)->permissionCatalog(
                $actor,
                ['per_page' => 100],
            )->through(PermissionListItemData::fromModel(...)),
        ] as $name => $read) {
            DB::flushQueryLog();
            DB::enableQueryLog();
            $read();
            $catalogReads = count(array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'sqlite_master')));
            $counts[$name] = count(DB::getQueryLog()) - $catalogReads;
            $counts[$name.'_ownership_probes'] = $catalogReads;
            expect($catalogReads)->toBeLessThanOrEqual(4);
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

it('checks canonical role name availability for the configured guard', function (): void {
    $actor = $this->user('rbac-availability@example.test');
    $webRole = Role::factory()->create(['name' => 'editor', 'guard_name' => 'web']);
    Role::factory()->create(['name' => 'api-only', 'guard_name' => 'api']);

    $conflict = RoleNameAvailabilityData::from(app(AuthRbacReader::class)->roleNameAvailability($actor, '  editor  '));
    $unchanged = RoleNameAvailabilityData::from(app(AuthRbacReader::class)->roleNameAvailability($actor, 'editor', $webRole->id));
    $otherGuard = RoleNameAvailabilityData::from(app(AuthRbacReader::class)->roleNameAvailability($actor, 'api-only'));

    expect($conflict->toArray())->toBe([
        'name' => 'editor',
        'available' => false,
        'conflictingRoleId' => $webRole->id,
    ])->and($unchanged->available)->toBeTrue()
        ->and($unchanged->conflictingRoleId)->toBeNull()
        ->and($otherGuard->available)->toBeTrue()
        ->and(fn () => RoleNameAvailabilityData::from(app(AuthRbacReader::class)->roleNameAvailability($actor, '   ')))
        ->toThrow(AuthException::class, 'between one and 160')
        ->and(fn () => RoleNameAvailabilityData::from(app(AuthRbacReader::class)->roleNameAvailability($actor, 'editor', 'not-a-uuid')))
        ->toThrow(AuthException::class, 'UUID');
});

it('resolves mixed role and permission identifiers into ordered DTOs with bounded queries', function (): void {
    $actor = $this->user('rbac-resolution@example.test');
    $editor = Role::factory()->create(['name' => 'editor']);
    $publisher = Role::factory()->create(['name' => 'publisher']);
    $read = Permission::factory()->create(['name' => 'content.read']);
    $write = Permission::factory()->create(['name' => 'content.write']);

    DB::flushQueryLog();
    DB::enableQueryLog();
    $roles = app(AuthRbacReader::class)->resolveRoles($actor, [$publisher->id, 'editor'])->map(RoleOptionData::fromModel(...));
    $roleQueryCount = count(authProtectedRbacReads(DB::getQueryLog()));
    DB::flushQueryLog();
    $permissions = app(AuthRbacReader::class)->resolvePermissions($actor, ['content.write', $read->id])->map(PermissionOptionData::fromModel(...));
    $permissionQueryCount = count(authProtectedRbacReads(DB::getQueryLog()));
    DB::disableQueryLog();

    expect($roles)->toHaveCount(2)
        ->and($roles->every(fn (mixed $role): bool => $role instanceof RoleOptionData))->toBeTrue()
        ->and($roles->pluck('id')->all())->toBe([$publisher->id, $editor->id])
        ->and($permissions)->toHaveCount(2)
        ->and($permissions->every(fn (mixed $permission): bool => $permission instanceof PermissionOptionData))->toBeTrue()
        ->and($permissions->pluck('id')->all())->toBe([$write->id, $read->id])
        ->and($roleQueryCount)->toBeGreaterThan(0)->toBeLessThanOrEqual(2)
        ->and($permissionQueryCount)->toBeGreaterThan(0)->toBeLessThanOrEqual(2);
});

it('keeps the existing entity locator construction contract source compatible', function (): void {
    $role = Role::factory()->create(['name' => 'legacy-constructor-role']);
    $locator = new RbacEntityLocator(app(AuthModelRegistry::class));

    expect($locator->rolesByIdentifiers([$role->id])->sole()->is($role))->toBeTrue();
});

it('rejects invalid, missing, ambiguous, duplicate, and cross-guard RBAC identifiers', function (): void {
    $actor = $this->user('rbac-resolution-errors@example.test');
    $role = Role::factory()->create(['name' => 'editor']);
    Role::factory()->create(['name' => $role->id]);
    $apiRole = Role::factory()->create(['name' => 'api-editor', 'guard_name' => 'api']);
    $permission = Permission::factory()->create(['name' => 'content.read']);

    expect(fn () => app(AuthRbacReader::class)->resolveRoles($actor, [''])->map(RoleOptionData::fromModel(...)))
        ->toThrow(AuthException::class, 'empty')
        ->and(fn () => app(AuthRbacReader::class)->resolveRoles($actor, ['editor', ' editor '])->map(RoleOptionData::fromModel(...)))
        ->toThrow(AuthException::class, 'duplicate')
        ->and(fn () => app(AuthRbacReader::class)->resolvePermissions($actor, [$permission->id, 'content.read'])->map(PermissionOptionData::fromModel(...)))
        ->toThrow(AuthException::class, 'same permission')
        ->and(fn () => app(AuthRbacReader::class)->resolveRoles($actor, [$role->id])->map(RoleOptionData::fromModel(...)))
        ->toThrow(AuthException::class, 'ambiguous')
        ->and(fn () => app(AuthRbacReader::class)->resolveRoles($actor, [$apiRole->id])->map(RoleOptionData::fromModel(...)))
        ->toThrow(AuthException::class, 'not found')
        ->and(fn () => app(AuthRbacReader::class)->resolvePermissions($actor, ['missing.permission'])->map(PermissionOptionData::fromModel(...)))
        ->toThrow(AuthException::class, 'not found')
        ->and(fn () => app(AuthRbacReader::class)->resolveRoles($actor, array_fill(0, 101, 'role'))->map(RoleOptionData::fromModel(...)))
        ->toThrow(AuthException::class, '100');
});

it('denies RBAC availability and resolution before querying package storage', function (): void {
    $actor = $this->user('rbac-resolution-denied@example.test');
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return false;
        }
    });

    foreach ([
        static fn () => RoleNameAvailabilityData::from(app(AuthRbacReader::class)->roleNameAvailability($actor, 'editor')),
        static fn () => app(AuthRbacReader::class)->resolveRoles($actor, ['editor'])->map(RoleOptionData::fromModel(...)),
        static fn () => app(AuthRbacReader::class)->resolvePermissions($actor, ['content.read'])->map(PermissionOptionData::fromModel(...)),
    ] as $read) {
        DB::flushQueryLog();
        DB::enableQueryLog();

        expect($read)->toThrow(AuthException::class, 'not authorized')
            ->and(DB::getQueryLog())->toBe([]);

        DB::disableQueryLog();
    }
});

it('adds and synchronizes role permissions through atomic assignment seams', function (): void {
    $actor = $this->user('rbac-assignments@example.test');
    $role = Role::factory()->create(['name' => 'editor']);
    $systemRole = Role::factory()->create(['name' => 'system-editor', 'is_system' => true]);
    $archive = Permission::factory()->create(['name' => 'content.archive']);
    $publish = Permission::factory()->create(['name' => 'content.publish']);
    $read = Permission::factory()->create(['name' => 'content.read']);
    $role->givePermissionTo($read);
    Event::fake([RbacChanged::class]);
    $initialAuditCount = AuthAudit::query()->count();

    $added = app(AuthRoles::class)->addPermissions($actor, $role, [$publish->id, 'content.archive']);
    $addedPermissionNames = $added->permissions->pluck('name')->all();
    $synchronized = app(AuthRoles::class)->syncPermissions($actor, $role, [$publish->id]);
    $synchronizedPermissionNames = $synchronized->permissions->pluck('name')->all();
    $cleared = app(AuthRoles::class)->syncPermissions($actor, $role, []);
    $clearedPermissionNames = $cleared->permissions->pluck('name')->all();
    $system = app(AuthRoles::class)->syncPermissions($actor, $systemRole, [$read->id]);

    expect($addedPermissionNames)->toBe([
        'content.archive',
        'content.publish',
        'content.read',
    ])->and($synchronizedPermissionNames)->toBe(['content.publish'])
        ->and($clearedPermissionNames)->toBe([])
        ->and($system->name)->toBe('system-editor')
        ->and($system->is_system)->toBeTrue()
        ->and($system->permissions->pluck('name')->all())->toBe(['content.read'])
        ->and(AuthAudit::query()->whereIn('action', [
            'role.permissions_added',
            'role.permissions_synchronized',
        ])->count())->toBe(4)
        ->and(AuthAudit::query()->count())->toBe($initialAuditCount + 4);

    Event::assertDispatchedTimes(RbacChanged::class, 4);
    Event::assertDispatched(RbacChanged::class, static fn (RbacChanged $event): bool => $event->entityType === 'role'
        && $event->entityId === $role->id
        && $event->operation === 'permissions_added'
        && $event->payload['permission_names'] === ['content.archive', 'content.publish']);
});

it('rejects invalid role assignment inputs without changing existing permissions', function (): void {
    $actor = $this->user('rbac-invalid-assignment@example.test');
    $role = Role::factory()->create(['name' => 'editor']);
    $permission = Permission::factory()->create(['name' => 'content.read']);
    $role->givePermissionTo($permission);

    expect(fn () => app(AuthRoles::class)->addPermissions($actor, $role, [$permission->id, $permission->id]))
        ->toThrow(AuthException::class, 'duplicate')
        ->and(fn () => app(AuthRoles::class)->syncPermissions($actor, $role, ['missing.permission']))
        ->toThrow(AuthException::class, 'not found')
        ->and($role->fresh()->permissions()->pluck('name')->all())->toBe(['content.read']);
});

it('creates a permission with initial roles atomically and rolls back unresolved assignments', function (): void {
    $actor = $this->user('rbac-create-with-roles@example.test');
    $editor = Role::factory()->create(['name' => 'editor']);
    $publisher = Role::factory()->create(['name' => 'publisher']);
    Event::fake([RbacChanged::class]);
    $initialAuditCount = AuthAudit::query()->count();

    $permission = app(AuthPermissions::class)->createWithRoles(
        $actor,
        ['name' => 'content.publish', 'group' => 'content', 'metadata' => ['scope' => 'global']],
        [$publisher->id, 'editor'],
    );

    expect($permission->roles->pluck('name')->all())->toBe(['editor', 'publisher'])
        ->and($permission->group)->toBe('content')
        ->and($permission->metadata)->toBe(['scope' => 'global'])
        ->and(AuthAudit::query()->where('action', 'permission.created_with_roles')->count())->toBe(1)
        ->and(AuthAudit::query()->count())->toBe($initialAuditCount + 1);
    Event::assertDispatchedTimes(RbacChanged::class, 1);

    expect(fn () => app(AuthPermissions::class)->createWithRoles(
        $actor,
        ['name' => 'content.missing-role'],
        ['missing-role'],
    ))->toThrow(AuthException::class, 'not found')
        ->and(Permission::query()->where('name', 'content.missing-role')->exists())->toBeFalse();
    Event::assertDispatchedTimes(RbacChanged::class, 1);
});

it('keeps maximum multibyte assignment audits within the package byte boundary', function (): void {
    $actor = $this->user('rbac-bounded-audit@example.test');
    $role = Role::factory()->create(['name' => 'bounded-audit-role']);
    $permissions = collect(range(1, 100))->map(
        static fn (int $index): Permission => Permission::factory()->create([
            'name' => str_repeat('π', 150).sprintf('%010d', $index),
        ]),
    );
    Event::fake([RbacChanged::class]);

    $updated = app(AuthRoles::class)->addPermissions(
        $actor,
        $role,
        $permissions->pluck('id')->all(),
    );

    expect($updated->permissions)->toHaveCount(100)
        ->and(AuthAudit::query()->where('action', 'role.permissions_added')->count())->toBe(1);
    Event::assertDispatchedTimes(RbacChanged::class, 1);
});

it('rolls back permission creation when its required audit cannot be recorded', function (): void {
    $actor = $this->user('rbac-audit-rollback@example.test');
    $role = Role::factory()->create(['name' => 'audit-rollback-role']);
    app()->instance(AuthAuditRecorder::class, new class implements AuthAuditRecorder
    {
        public function record(
            string $action,
            string $outcome = 'success',
            ?SubjectReference $subject = null,
            ?Authenticatable $actor = null,
            ?string $clientId = null,
            array $metadata = [],
        ): ?object {
            throw new RuntimeException('Audit recorder unavailable.');
        }
    });
    Event::fake([RbacChanged::class]);

    expect(fn () => app(AuthPermissions::class)->createWithRoles(
        $actor,
        ['name' => 'content.audit-rollback'],
        [$role->id],
    ))->toThrow(RuntimeException::class, 'Audit recorder unavailable')
        ->and(Permission::query()->where('name', 'content.audit-rollback')->exists())->toBeFalse()
        ->and($role->fresh()->permissions)->toBeEmpty();
    Event::assertNotDispatched(RbacChanged::class);
});

it('authorizes assignment seams before loading or writing RBAC state', function (): void {
    $actor = $this->user('rbac-assignment-denied@example.test');
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return false;
        }
    });

    foreach ([
        static fn () => app(AuthRoles::class)->addPermissions($actor, 'role-id', ['permission-id']),
        static fn () => app(AuthRoles::class)->syncPermissions($actor, 'role-id', []),
        static fn () => app(AuthPermissions::class)->createWithRoles(
            $actor,
            ['name' => 'content.denied'],
            ['role-id'],
        ),
    ] as $write) {
        DB::flushQueryLog();
        DB::enableQueryLog();

        expect($write)->toThrow(AuthException::class, 'not authorized')
            ->and(DB::getQueryLog())->toBe([]);

        DB::disableQueryLog();
    }
});

it('returns bounded per-role analytics using configured principal semantics', function (): void {
    Schema::table(AuthTables::Users, static function (Blueprint $table): void {
        $table->boolean('enabled_for_access')->default(true);
    });
    config()->set(
        'nvl-auth.features.principal_management.settings.attributes.active',
        'enabled_for_access',
    );
    $actor = $this->user('rbac-role-analytics@example.test');
    $parent = Role::factory()->create(['name' => 'manager']);
    $role = Role::factory()->create(['name' => 'editor', 'parent_id' => $parent->id]);
    $firstChild = Role::factory()->create(['name' => 'editor-a', 'parent_id' => $role->id]);
    Role::factory()->create(['name' => 'editor-b', 'parent_id' => $role->id]);
    Role::factory()->create(['name' => 'editor-a-child', 'parent_id' => $firstChild->id]);
    $permissions = collect([
        ['name' => 'content.read', 'group' => 'content'],
        ['name' => 'content.write', 'group' => "\t content \n"],
        ['name' => 'users.read', 'group' => 'identity'],
        ['name' => 'misc.read', 'group' => '   '],
    ])->map(static fn (array $attributes): Permission => Permission::factory()->create($attributes));
    $role->givePermissionTo($permissions);

    foreach ([true, true, false] as $index => $active) {
        $user = $this->user("role-analytics-{$index}@example.test");
        $user->forceFill(['enabled_for_access' => $active])->save();
        $user->assignRole($role);
    }

    $analytics = RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $role->id));

    expect($analytics)->toBeInstanceOf(RoleAnalyticsData::class)
        ->and($analytics->toArray())->toMatchArray([
            'roleId' => $role->id,
            'users' => 3,
            'activeUsers' => 2,
            'inactiveUsers' => 1,
            'permissions' => 4,
            'children' => 2,
            'descendants' => 3,
            'parentName' => 'manager',
            'permissionGroups' => [
                'content' => 2,
                'general' => 1,
                'identity' => 1,
            ],
        ])
        ->and(array_keys($analytics->toArray()))
        ->not->toContain('userIds')
        ->not->toContain('usersData')
        ->not->toContain('email');
});

it('counts an independently configured RBAC principal model', function (): void {
    $actor = $this->user('rbac-host-analytics@example.test');
    Schema::create('host_analytics_principals', static function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->string('name');
        $table->string('email')->unique();
        $table->boolean('enabled_for_access')->default(true);
        $table->timestamps();
    });
    config()->set('nvl-auth.features.rbac.models.principal', HostAnalyticsPrincipal::class);
    config()->set(
        'nvl-auth.features.principal_management.settings.attributes.active',
        'enabled_for_access',
    );
    $role = Role::factory()->create(['name' => 'host-editor']);

    foreach ([true, true, false] as $index => $active) {
        $principal = HostAnalyticsPrincipal::query()->create([
            'name' => "Host Principal {$index}",
            'email' => "host-principal-{$index}@example.test",
            'enabled_for_access' => $active,
        ]);
        $principal->assignRole($role);
    }

    $analytics = RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $role->id));

    expect($analytics->users)->toBe(3)
        ->and($analytics->activeUsers)->toBe(2)
        ->and($analytics->inactiveUsers)->toBe(1);
});

it('restricts role analytics to the configured role model and guard', function (): void {
    config()->set('nvl-auth.features.rbac.models.role', HostRbacRole::class);
    config()->set('nvl-auth.features.rbac.settings.guard', 'web');
    $actor = $this->user('rbac-role-boundary@example.test');
    $configuredRole = HostRbacRole::query()->create([
        'name' => 'configured-editor',
        'guard_name' => 'web',
    ]);
    $crossGuardRole = HostRbacRole::query()->create([
        'name' => 'api-editor',
        'guard_name' => 'api',
    ]);
    $unconfiguredModel = Role::factory()->create(['name' => 'base-editor']);

    expect(RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $configuredRole->id))->roleId)
        ->toBe($configuredRole->id)
        ->and(fn () => RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $crossGuardRole->id)))
        ->toThrow(ModelNotFoundException::class)
        ->and(fn () => RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $unconfiguredModel)))
        ->toThrow(ModelNotFoundException::class);
});

it('keeps role analytics query count constant as related data grows', function (): void {
    $actor = $this->user('rbac-role-analytics-query-count@example.test');
    $createFixture = function (string $prefix, int $size): Role {
        $role = Role::factory()->create(['name' => "{$prefix}-role"]);

        for ($index = 0; $index < $size; $index++) {
            Role::factory()->create([
                'name' => "{$prefix}-child-{$index}",
                'parent_id' => $role->id,
            ]);
            $permission = Permission::factory()->create([
                'name' => "{$prefix}.permission.{$index}",
                'group' => "{$prefix}-group",
            ]);
            $role->givePermissionTo($permission);
            $this->user("{$prefix}-user-{$index}@example.test")->assignRole($role);
        }

        return $role;
    };
    $small = $createFixture('small', 1);
    $large = $createFixture('large', 25);
    $measure = function (Role $role) use ($actor): array {
        DB::flushQueryLog();
        DB::enableQueryLog();
        RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $role->id));
        $queries = authProtectedRbacReads(DB::getQueryLog());
        DB::disableQueryLog();

        return $queries;
    };

    $smallQueries = $measure($small);
    $largeQueries = $measure($large);
    $permissionGroupQuery = collect($largeQueries)->first(
        static fn (array $query): bool => str_contains($query['query'], 'permissions_count'),
    );
    $permissionGroupSql = is_array($permissionGroupQuery)
        ? str_replace(['`', '"', '[', ']'], '', mb_strtolower($permissionGroupQuery['query']))
        : '';

    expect($smallQueries)->toHaveCount(4)
        ->and($largeQueries)->toHaveCount(4)
        ->and($permissionGroupSql)->toContain('group by normalized_group')
        ->and(collect($largeQueries)->pluck('query')->implode(' '))->not->toContain('activity');
});

it('counts role descendants once when persisted hierarchy data contains a cycle', function (): void {
    $actor = $this->user('rbac-role-analytics-cycle@example.test');
    $first = Role::factory()->create(['name' => 'cycle-first']);
    $second = Role::factory()->create(['name' => 'cycle-second', 'parent_id' => $first->id]);
    Role::factory()->create(['name' => 'cycle-child', 'parent_id' => $second->id]);
    $first->forceFill(['parent_id' => $second->id])->save();

    $analytics = RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, $first->id));

    expect($analytics->children)->toBe(1)
        ->and($analytics->descendants)->toBe(2)
        ->and($analytics->parentName)->toBe('cycle-second');
});

it('denies per-role analytics before querying package storage', function (): void {
    $actor = $this->user('rbac-role-analytics-denied@example.test');
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return false;
        }
    });
    DB::flushQueryLog();
    DB::enableQueryLog();

    expect(fn () => RoleAnalyticsData::from(app(AuthRbacReader::class)->roleAnalytics($actor, 'role-id')))
        ->toThrow(AuthException::class, 'not authorized')
        ->and(DB::getQueryLog())->toBe([]);

    DB::disableQueryLog();
});

/** @param list<array{query: string, bindings: array, time: float}> $queries
 * @return list<array{query: string, bindings: array, time: float}>
 */
function authProtectedRbacReads(array $queries): array
{
    $tables = [config('permission.table_names.roles'), config('permission.table_names.permissions'), config('permission.table_names.model_has_roles'), config('permission.table_names.model_has_permissions'), config('permission.table_names.role_has_permissions'), (new TestUser)->getTable()];

    return array_values(array_filter($queries, static function (array $query) use ($tables): bool {
        $sql = str_replace(['`', '"', '[', ']'], '', strtolower($query['query']));
        foreach ($tables as $table) {
            if (is_string($table) && preg_match('/\\b(?:from|join)\\s+'.preg_quote($table, '/').'\\b/', $sql) === 1) {
                return true;
            }
        }

        return false;
    }));
}
