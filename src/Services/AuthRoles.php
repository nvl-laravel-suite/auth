<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Events\DomainEventDispatcher;
use Spatie\Permission\PermissionRegistrar;

/** Complete native AuthRoles operations.
 * @api
 */
final readonly class AuthRoles
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private ManagementAuthorizer $authorization, private AuthModelRegistry $models, private RbacEntityLocator $entities, private RoleHierarchy $hierarchy, private AuthConfiguration $configuration, private AuthAuditRecorder $audits, private DomainEventDispatcher $domainEvents, private RbacAssignmentService $assignments, private RoleTemplateRegistry $templates, private RbacSynchronizer $synchronizer, private Container $rbacContainer, private MutationAuthorizer $syncUserRolesAuthorization, private RbacPrincipalAccess $principals, private RbacManager $rbac) {}

    /** Persist one role.
     * @param  array<string, mixed>  $data
     */
    public function create(Authenticatable $actor, array $data): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $data = $this->validateStoreRole($data);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $class = $this->models->roleClass();
        $connection = (new $class)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $class, $data): Role {
            $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
            $parent = $data['parentId'] !== null ? $this->entities->role($data['parentId']) : null;
            /** @var array{name: string, guard_name: string, display_name: string|null, description: string|null, parent_id: null, priority: int, is_system: bool, metadata: array<string, mixed>|null} $attributes */
            $attributes = [...[], 'name' => trim($data['name']), 'guard_name' => $guard, 'display_name' => $data['displayName'], 'description' => $data['description'], 'parent_id' => null, 'priority' => $data['priority'], 'is_system' => $data['system'], 'metadata' => $data['metadata']];
            $role = $class::query()->create($attributes);
            $this->hierarchy->assertParentAllowed($role, $parent);
            $role->forceFill(['parent_id' => $parent?->id])->save();
            $role->syncPermissions($data['permissions']);
            $this->audits->record('role.created', actor: $actor, metadata: ['role_id' => $role->id]);
            $this->domainEvents->dispatch(new RbacChanged('role', $role->id, 'created', ['name' => $role->name]), $role->getConnection());

            return $role->refresh()->load(['parent', 'permissions']);
        }, 3);
    }

    /** Persist one role mutation.
     * @param  array<string, mixed>  $data
     */
    public function update(Authenticatable $actor, Role|string $role, array $data): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $data = $this->validateUpdateRole($data);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $role = $this->entities->role($role);
        if ($role->is_system && $role->name !== trim($data['name'])) {
            throw new AuthException('system_role_immutable', 'System role names cannot be changed.', 422);
        }

        return DB::connection($role->getConnectionName())->transaction(function () use ($actor, $data, $role): Role {
            $parent = $data['parentId'] !== null ? $this->entities->role($data['parentId']) : null;
            $this->hierarchy->assertParentAllowed($role, $parent);
            $role->fill(['name' => trim($data['name']), 'display_name' => $data['displayName'], 'description' => $data['description'], 'parent_id' => $parent?->id, 'priority' => $data['priority'], 'metadata' => $data['metadata']])->save();
            $role->syncPermissions($data['permissions']);
            $this->audits->record('role.updated', actor: $actor, metadata: ['role_id' => $role->id]);
            $this->domainEvents->dispatch(new RbacChanged('role', $role->id, 'updated'), $role->getConnection());

            return $role->refresh()->load(['parent', 'permissions']);
        }, 3);
    }

    /** Delete one role. */
    public function delete(Authenticatable $actor, Role|string $role): bool
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $role = $this->entities->role($role);
        if ($role->is_system) {
            throw new AuthException('system_role_delete_forbidden', 'System roles cannot be deleted.', 422);
        }

        return DB::connection($role->getConnectionName())->transaction(function () use ($actor, $role): bool {
            $identifier = $role->id;
            $deleted = (bool) $role->delete();
            $this->audits->record('role.deleted', actor: $actor, metadata: ['role_id' => $identifier]);
            $this->domainEvents->dispatch(new RbacChanged('role', $identifier, 'deleted'), $role->getConnection());

            return $deleted;
        }, 3);
    }

    /** Clone one role. */
    public function duplicate(Authenticatable $actor, Role|string $role, string $name, ?string $displayName = null): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $source = $this->entities->role($role)->load('permissions');
        $class = $this->models->roleClass();

        return DB::connection($source->getConnectionName())->transaction(function () use ($actor, $class, $displayName, $name, $source): Role {
            /** @var array{name: string, guard_name: string, display_name: string|null, description: string|null, parent_id: string|null, priority: int, is_system: bool, metadata: array<string, mixed>|null} $attributes */
            $attributes = [...[], 'name' => trim($name), 'guard_name' => $source->guard_name, 'display_name' => $displayName, 'description' => $source->description, 'parent_id' => $source->parent_id, 'priority' => $source->priority, 'is_system' => false, 'metadata' => $source->metadata];
            $clone = $class::query()->create($attributes);
            $clone->syncPermissions($source->permissions);
            $this->audits->record('role.cloned', actor: $actor, metadata: ['role_id' => $clone->id, 'source_role_id' => $source->id]);
            $this->domainEvents->dispatch(new RbacChanged('role', $clone->id, 'cloned', ['source_role_id' => $source->id]), $clone->getConnection());

            return $clone->refresh()->load('permissions');
        }, 3);
    }

    /**
     * Add a bounded set of permission IDs or names atomically.
     *
     * @param  list<string>  $permissionIdentifiers
     */
    public function addPermissions(Authenticatable $actor, Role|string $role, array $permissionIdentifiers): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $result = DB::connection($this->assignments->roleConnectionName($role))->transaction(function () use ($actor, $permissionIdentifiers, $role): array {
            $result = $this->assignments->add($role, $permissionIdentifiers);
            $this->audits->record('role.permissions_added', actor: $actor, metadata: ['role_id' => $result['role']->id, 'permission_ids' => $result['permissionIds'], 'permission_count' => count($result['permissionIds'])]);
            $this->domainEvents->dispatch(new RbacChanged('role', $result['role']->id, 'permissions_added', ['permission_ids' => $result['permissionIds'], 'permission_names' => $result['permissionNames']]), $result['role']->getConnection());

            return $result;
        }, 3);
        $this->assignments->clearPermissionCache();

        return $result['role'];
    }

    /**
     * Synchronize a bounded set of permission IDs or names atomically.
     *
     * @param  list<string>  $permissionIdentifiers
     */
    public function syncPermissions(Authenticatable $actor, Role|string $role, array $permissionIdentifiers): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $result = DB::connection($this->assignments->roleConnectionName($role))->transaction(function () use ($actor, $permissionIdentifiers, $role): array {
            $result = $this->assignments->synchronize($role, $permissionIdentifiers);
            $this->audits->record('role.permissions_synchronized', actor: $actor, metadata: ['role_id' => $result['role']->id, 'permission_ids' => $result['permissionIds'], 'permission_count' => count($result['permissionIds'])]);
            $this->domainEvents->dispatch(new RbacChanged('role', $result['role']->id, 'permissions_synchronized', ['permission_ids' => $result['permissionIds'], 'permission_names' => $result['permissionNames']]), $result['role']->getConnection());

            return $result;
        }, 3);
        $this->assignments->clearPermissionCache();

        return $result['role'];
    }

    /** Apply one named template.
     * @param  array<string, mixed>  $data
     */
    public function applyTemplate(Authenticatable $actor, array $data): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $data = $this->validateApplyRoleTemplate($data);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        $templates = $this->templates->roles();
        $templateKey = trim($data['template']);
        if (! array_key_exists($templateKey, $templates)) {
            throw new AuthException('role_template_not_found', 'The requested role template does not exist.', 404);
        }
        $template = $templates[$templateKey];
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new $roleClass)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $data, $guard, $permissionClass, $roleClass, $template, $templateKey): Role {
            $parent = $template->parentRole !== null ? $this->entities->roleByName($template->parentRole, $guard) : null;
            $mutation = $template->toMutation($data['roleName'], $parent?->id);
            try {
                $role = $this->entities->roleByName($mutation['name'], $guard);
            } catch (ModelNotFoundException) {
                /** @var array{name: string, guard_name: string} $attributes */
                $attributes = [...[], 'name' => $mutation['name'], 'guard_name' => $guard];
                $role = $roleClass::query()->create($attributes);
            }
            $this->hierarchy->assertParentAllowed($role, $parent);
            $permissions = array_map(static fn (string $name) => $permissionClass::findOrCreate($name, $guard), $mutation['permissions']);
            $attributes = ['name' => $mutation['name'], 'display_name' => $mutation['displayName'], 'description' => $mutation['description'], 'parent_id' => $mutation['parentId'], 'priority' => $mutation['priority'], 'system' => $mutation['system'], 'metadata' => $mutation['metadata']];
            $attributes['is_system'] = $attributes['system'];
            unset($attributes['system']);
            $role->fill($attributes)->save();
            $role->syncPermissions($permissions);
            $this->audits->record('role.template_applied', actor: $actor, metadata: ['role_id' => $role->id, 'template' => $templateKey, 'target_role' => $mutation['name']]);
            $this->domainEvents->dispatch(new RbacChanged('role', $role->id, 'template_applied', ['template' => $templateKey, 'target_role' => $mutation['name']]), $role->getConnection());

            return $role->refresh()->load(['parent', 'permissions']);
        }, 3);
    }

    /**
     * Synchronize every configured role template and return the role count.
     */
    public function synchronizeTemplates(Authenticatable $actor): int
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new Role)->getConnectionName();
        $roleCount = DB::connection($connection)->transaction(fn (): int => $this->synchronizer->synchronizeRoles($guard), 3);
        $this->registrar()->forgetCachedPermissions();
        $this->audits->record('rbac.roles_synchronized', actor: $actor, metadata: ['roles' => $roleCount, 'guard' => $guard]);

        return $roleCount;
    }

    /** Synchronize one validated role assignment atomically.
     * @param  array<string, mixed>  $data
     */
    public function syncUserRoles(Authenticatable|SystemMutationContext $authority, Authenticatable|string $user, array $data): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $data = $this->validateSyncUserRoles($data);
        $ability = 'nvl.auth.users.manageAccess';
        $actor = $this->syncUserRolesAuthorization->authorize($authority, $ability, $user);
        $metadata = $this->syncUserRolesAuthorization->metadata($authority);
        $user = $this->principals->find($user);

        return DB::connection($this->principals->connectionName($user))->transaction(function () use ($actor, $data, $metadata, $user): Authenticatable {
            $this->rbac->syncRoles($user, $data['roles'], $metadata);
            $this->audits->record('user.roles_synchronized', subject: SubjectReference::fromAuthenticatable($user), actor: $actor, metadata: ['roles' => $data['roles'], ...$metadata]);

            return $this->rbac->refresh($user, ['roles']);
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{template: string, roleName: string|null}
     */
    private function validateApplyRoleTemplate(array $data): array
    {
        if (array_diff(array_keys($data), ['template', 'roleName']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['template'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [template].');
        }
        if (! array_key_exists('roleName', $data)) {
            $data['roleName'] = null;
        }
        if (! ($data['roleName'] === null || is_string($data['roleName']))) {
            throw new InvalidArgumentException('Invalid Auth input [roleName].');
        }
        Validator::make($data, ['template' => ['required', 'string', 'max:160'], 'roleName' => ['nullable', 'nullable', 'string', 'max:160']])->validate();
        if (trim($data['template']) === '' || mb_strlen($data['template']) > 160) {
            throw new InvalidArgumentException('Role template keys must contain between one and 160 characters.');
        }
        if ($data['roleName'] !== null && (trim($data['roleName']) === '' || mb_strlen($data['roleName']) > 160)) {
            throw new InvalidArgumentException('Target role names must contain between one and 160 characters.');
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, displayName: string|null, description: string|null, parentId: string|null, priority: int, system: bool, permissions: list<string>, metadata: array<array-key, mixed>}
     */
    private function validateStoreRole(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'displayName', 'description', 'parentId', 'priority', 'system', 'permissions', 'metadata']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! array_key_exists('displayName', $data)) {
            $data['displayName'] = null;
        }
        if (! ($data['displayName'] === null || is_string($data['displayName']))) {
            throw new InvalidArgumentException('Invalid Auth input [displayName].');
        }
        if (! array_key_exists('description', $data)) {
            $data['description'] = null;
        }
        if (! ($data['description'] === null || is_string($data['description']))) {
            throw new InvalidArgumentException('Invalid Auth input [description].');
        }
        if (! array_key_exists('parentId', $data)) {
            $data['parentId'] = null;
        }
        if (! ($data['parentId'] === null || is_string($data['parentId']))) {
            throw new InvalidArgumentException('Invalid Auth input [parentId].');
        }
        if (! array_key_exists('priority', $data)) {
            $data['priority'] = 0;
        }
        if (! is_int($data['priority'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [priority].');
        }
        if (! array_key_exists('system', $data)) {
            $data['system'] = false;
        }
        if (! is_bool($data['system'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [system].');
        }
        if (! array_key_exists('permissions', $data)) {
            $data['permissions'] = [];
        }
        if (! is_array($data['permissions'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [permissions].');
        }
        if (! array_is_list($data['permissions'])) {
            throw new InvalidArgumentException('Auth input [permissions] must be a list.');
        }
        $data['permissions'] = array_map(static function (mixed $value): string {
            if (! is_string($value)) {
                throw new InvalidArgumentException('Auth input [permissions] must contain strings.');
            }

            return $value;
        }, $data['permissions']);
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 160) {
            throw new InvalidArgumentException('Role names must contain between one and 160 characters.');
        }
        if ($data['displayName'] !== null && mb_strlen($data['displayName']) > 160) {
            throw new InvalidArgumentException('Role display names must not exceed 160 characters.');
        }
        if ($data['description'] !== null && mb_strlen($data['description']) > 2000) {
            throw new InvalidArgumentException('Role descriptions must not exceed 2,000 characters.');
        }
        if ($data['parentId'] !== null && ! preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $data['parentId'])) {
            throw new InvalidArgumentException('Role parent identifiers must be UUIDs.');
        }
        if ($data['priority'] < -100000 || $data['priority'] > 100000) {
            throw new InvalidArgumentException('Role priority must be between -100,000 and 100,000.');
        }
        if (count($data['permissions']) > 500) {
            throw new InvalidArgumentException('Role permissions must be a list containing at most 500 values.');
        }
        $seen = [];
        foreach ($data['permissions'] as $permission) {
            if (trim($permission) === '' || mb_strlen($permission) > 160) {
                throw new InvalidArgumentException('Role permission names must contain between one and 160 characters.');
            }
            if (isset($seen[$permission])) {
                throw new InvalidArgumentException('Role permission names must be distinct.');
            }
            $seen[$permission] = true;
        }
        try {
            $encodedMetadata = json_encode($data['metadata'], JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Role metadata must be JSON serializable.', previous: $exception);
        }
        if (strlen($encodedMetadata) > 65535) {
            throw new InvalidArgumentException('Role metadata must not exceed 65,535 encoded bytes.');
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{roles: list<string>}
     */
    private function validateSyncUserRoles(array $data): array
    {
        if (array_diff(array_keys($data), ['roles']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_array($data['roles'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [roles].');
        }
        if (! array_is_list($data['roles'])) {
            throw new InvalidArgumentException('Auth input [roles] must be a list.');
        }
        $data['roles'] = array_map(static function (mixed $value): string {
            if (! is_string($value)) {
                throw new InvalidArgumentException('Auth input [roles] must contain strings.');
            }

            return $value;
        }, $data['roles']);
        if (count($data['roles']) > 100 || count(array_unique($data['roles'])) !== count($data['roles'])) {
            throw new InvalidArgumentException('User roles must be a distinct list containing at most 100 names.');
        }
        foreach ($data['roles'] as $role) {
            if (trim($role) === '' || mb_strlen($role) > 160) {
                throw new InvalidArgumentException('User role names must contain between one and 160 characters.');
            }
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, displayName: string|null, description: string|null, parentId: string|null, priority: int, system: bool, permissions: list<string>, metadata: array<array-key, mixed>}
     */
    private function validateUpdateRole(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'displayName', 'description', 'parentId', 'priority', 'system', 'permissions', 'metadata']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! array_key_exists('displayName', $data)) {
            $data['displayName'] = null;
        }
        if (! ($data['displayName'] === null || is_string($data['displayName']))) {
            throw new InvalidArgumentException('Invalid Auth input [displayName].');
        }
        if (! array_key_exists('description', $data)) {
            $data['description'] = null;
        }
        if (! ($data['description'] === null || is_string($data['description']))) {
            throw new InvalidArgumentException('Invalid Auth input [description].');
        }
        if (! array_key_exists('parentId', $data)) {
            $data['parentId'] = null;
        }
        if (! ($data['parentId'] === null || is_string($data['parentId']))) {
            throw new InvalidArgumentException('Invalid Auth input [parentId].');
        }
        if (! array_key_exists('priority', $data)) {
            $data['priority'] = 0;
        }
        if (! is_int($data['priority'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [priority].');
        }
        if (! array_key_exists('system', $data)) {
            $data['system'] = false;
        }
        if (! is_bool($data['system'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [system].');
        }
        if (! array_key_exists('permissions', $data)) {
            $data['permissions'] = [];
        }
        if (! is_array($data['permissions'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [permissions].');
        }
        if (! array_is_list($data['permissions'])) {
            throw new InvalidArgumentException('Auth input [permissions] must be a list.');
        }
        $data['permissions'] = array_map(static function (mixed $value): string {
            if (! is_string($value)) {
                throw new InvalidArgumentException('Auth input [permissions] must contain strings.');
            }

            return $value;
        }, $data['permissions']);
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 160) {
            throw new InvalidArgumentException('Role names must contain between one and 160 characters.');
        }
        if ($data['displayName'] !== null && mb_strlen($data['displayName']) > 160) {
            throw new InvalidArgumentException('Role display names must not exceed 160 characters.');
        }
        if ($data['description'] !== null && mb_strlen($data['description']) > 2000) {
            throw new InvalidArgumentException('Role descriptions must not exceed 2,000 characters.');
        }
        if ($data['parentId'] !== null && ! preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $data['parentId'])) {
            throw new InvalidArgumentException('Role parent identifiers must be UUIDs.');
        }
        if ($data['priority'] < -100000 || $data['priority'] > 100000) {
            throw new InvalidArgumentException('Role priority must be between -100,000 and 100,000.');
        }
        if (count($data['permissions']) > 500) {
            throw new InvalidArgumentException('Role permissions must be a list containing at most 500 values.');
        }
        $seen = [];
        foreach ($data['permissions'] as $permission) {
            if (trim($permission) === '' || mb_strlen($permission) > 160) {
                throw new InvalidArgumentException('Role permission names must contain between one and 160 characters.');
            }
            if (isset($seen[$permission])) {
                throw new InvalidArgumentException('Role permission names must be distinct.');
            }
            $seen[$permission] = true;
        }
        try {
            $encodedMetadata = json_encode($data['metadata'], JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Role metadata must be JSON serializable.', previous: $exception);
        }
        if (strlen($encodedMetadata) > 65535) {
            throw new InvalidArgumentException('Role metadata must not exceed 65,535 encoded bytes.');
        }

        return $data;
    }

    /** Native Auth operation. */
    private function registrar(): PermissionRegistrar
    {
        if (! class_exists(PermissionRegistrar::class)) {
            throw AuthException::invalidConfiguration('RBAC requires spatie/laravel-permission.');
        }

        return $this->rbacContainer->make(PermissionRegistrar::class);
    }
}
