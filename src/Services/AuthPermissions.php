<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Events\DomainEventDispatcher;
use Spatie\Permission\PermissionRegistrar;

/**
 * Complete native AuthPermissions operations.
 *
 * @api
 */
final readonly class AuthPermissions
{
    /** Create the permission management service. */
    public function __construct(private FeatureGate $features, private ManagementAuthorizer $authorization, private AuthModelRegistry $models, private AuthConfiguration $configuration, private AuthAuditRecorder $audits, private AuthCommittedAudit $committedAudits, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents, private RbacAssignmentService $assignments, private RbacEntityLocator $entities, private RbacSynchronizer $synchronizer, private Container $rbacContainer, private MutationAuthorizer $syncUserPermissionsAuthorization, private RbacPrincipalAccess $principals, private RbacManager $rbac, private MutationAuthorizer $bootstrapAuthorization) {}

    /** Persist one permission.
     * @param  array<string, mixed>  $data
     */
    public function create(Authenticatable $actor, array $data): Permission
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $data = $this->validateStorePermission($data);
        $this->operations->requirePlatformAdministration();
        $this->authorization->authorize($actor, 'nvl.auth.rbac.managePermissions');
        $class = $this->models->permissionClass();
        $connection = (new $class)->getConnectionName();

        $permission = DB::connection($connection)->transaction(function () use ($actor, $class, $data): Permission {
            $permission = $class::query()->create(['name' => trim($data['name']), 'guard_name' => $this->configuration->string('features.rbac.settings.guard', 'web'), 'display_name' => $data['displayName'], 'description' => $data['description'], 'group' => RbacPermissionGroupExpressions::normalize($data['group']), 'is_system' => $data['system'], 'metadata' => $data['metadata']]);
            $this->audits->record('permission.created', actor: $actor, metadata: ['permission_id' => $permission->id]);
            $this->domainEvents->dispatch(new RbacChanged('permission', $permission->id, 'created', ['name' => $permission->name]), $permission->getConnection());

            return $permission->refresh();
        }, 3);
        $this->assignments->clearPermissionCache();

        return $permission;
    }

    /**
     * Create one permission and attach all resolved roles in one transaction.
     *
     * @param  list<string>  $roleIdentifiers
     * @param  array<string, mixed>  $data
     */
    public function createWithRoles(Authenticatable $actor, array $data, array $roleIdentifiers = []): Permission
    {
        $this->operations->rejectMixedRbacOperation();
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $data = $this->validateStorePermission($data);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.managePermissions');
        if ($roleIdentifiers !== []) {
            $this->authorization->authorize($actor, 'nvl.auth.rbac.manageRoles');
        }
        $class = $this->models->permissionClass();
        $connection = (new $class)->getConnectionName();
        $result = DB::connection($connection)->transaction(function () use ($actor, $class, $data, $roleIdentifiers): array {
            $permission = $class::query()->create(['name' => trim($data['name']), 'guard_name' => $this->configuration->string('features.rbac.settings.guard', 'web'), 'display_name' => $data['displayName'], 'description' => $data['description'], 'group' => RbacPermissionGroupExpressions::normalize($data['group']), 'is_system' => $data['system'], 'metadata' => $data['metadata']]);
            $result = $this->assignments->attachPermissionToRoles($permission, $roleIdentifiers);
            $this->audits->record('permission.created_with_roles', actor: $actor, metadata: ['permission_id' => $result['permission']->id, 'role_ids' => $result['roleIds'], 'role_count' => count($result['roleIds'])]);
            $this->domainEvents->dispatch(new RbacChanged('permission', $result['permission']->id, 'created', ['name' => $result['permission']->name, 'role_ids' => $result['roleIds'], 'role_names' => $result['roleNames']]), $result['permission']->getConnection());

            return $result;
        }, 3);
        $this->assignments->clearPermissionCache();

        return $result['permission'];
    }

    /** Persist one permission mutation.
     * @param  array<string, mixed>  $data
     */
    public function update(Authenticatable $actor, Permission|string $permission, array $data): Permission
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $data = $this->validateUpdatePermission($data);
        $this->operations->requirePlatformAdministration();
        $this->authorization->authorize($actor, 'nvl.auth.rbac.managePermissions');
        $permission = $this->entities->permission($permission);
        if ($permission->is_system && $permission->name !== trim($data['name'])) {
            throw new AuthException('system_permission_immutable', 'System permission names cannot be changed.', 422);
        }

        $permission = DB::connection($permission->getConnectionName())->transaction(function () use ($actor, $data, $permission): Permission {
            $permission->fill(['name' => trim($data['name']), 'display_name' => $data['displayName'], 'description' => $data['description'], 'group' => RbacPermissionGroupExpressions::normalize($data['group']), 'metadata' => $data['metadata']])->save();
            $this->audits->record('permission.updated', actor: $actor, metadata: ['permission_id' => $permission->id]);
            $this->domainEvents->dispatch(new RbacChanged('permission', $permission->id, 'updated'), $permission->getConnection());

            return $permission->refresh();
        }, 3);
        $this->assignments->clearPermissionCache();

        return $permission;
    }

    /** Delete one permission. */
    public function delete(Authenticatable $actor, Permission|string $permission): bool
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Revoke);
        $this->operations->requirePlatformAdministration();
        $this->authorization->authorize($actor, 'nvl.auth.rbac.managePermissions');
        $permission = $this->entities->permission($permission);
        if ($permission->is_system) {
            throw new AuthException('system_permission_delete_forbidden', 'System permissions cannot be deleted.', 422);
        }

        $deleted = DB::connection($permission->getConnectionName())->transaction(function () use ($actor, $permission): bool {
            $identifier = $permission->id;
            $deleted = (bool) $permission->delete();
            $this->audits->record('permission.deleted', actor: $actor, metadata: ['permission_id' => $identifier]);
            $this->domainEvents->dispatch(new RbacChanged('permission', $identifier, 'deleted'), $permission->getConnection());

            return $deleted;
        }, 3);
        $this->assignments->clearPermissionCache();

        return $deleted;
    }

    /**
     * Create missing permissions without deleting host-owned records.
     */
    public function synchronizeCatalog(Authenticatable $actor): int
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->operations->requirePlatformAdministration();
        $this->authorization->authorize($actor, 'nvl.auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $permissionClass = $this->models->permissionClass();
        $connection = (new $permissionClass)->getConnection();
        $created = $connection->transaction(fn (): int => $this->synchronizer->synchronizePermissions($guard), 3);
        $this->registrar()->forgetCachedPermissions();
        $this->committedAudits->afterCommit($connection, 'rbac.permissions_synchronized', actor: $actor, metadata: ['created' => $created, 'guard' => $guard]);

        return $created;
    }

    /** Synchronize one validated direct permission assignment atomically.
     * @param  array<string, mixed>  $data
     */
    public function syncUserPermissions(Authenticatable|SystemMutationContext $authority, Authenticatable|string $user, array $data): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $data = $this->validateSyncUserPermissions($data);
        $ability = 'nvl.auth.users.manageAccess';
        $actor = $this->syncUserPermissionsAuthorization->authorize($authority, $ability, $user);
        $metadata = $this->syncUserPermissionsAuthorization->metadata($authority);
        $user = $this->principals->find($user);

        return DB::connection($this->principals->connectionName($user))->transaction(function () use ($actor, $data, $metadata, $user): Authenticatable {
            $this->rbac->syncPermissions($user, $data['permissions'], $metadata);
            $this->audits->record('user.permissions_synchronized', subject: SubjectReference::fromAuthenticatable($user), actor: $actor, metadata: ['permissions' => $data['permissions'], ...$metadata]);

            return $this->rbac->refresh($user, ['permissions']);
        }, 3);
    }

    /**
     * Synchronize permission catalogs and role templates in one transaction.
     *
     * @return array<string, mixed>
     */
    public function synchronize(Authenticatable $actor): array
    {
        $this->operations->rejectMixedRbacOperation();
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = $this->synchronizer->roleConnection();
        $result = $connection->transaction(function () use ($guard): array {
            return ['permissionsCreated' => $this->synchronizer->synchronizePermissions($guard), 'rolesSynchronized' => $this->synchronizer->synchronizeRoles($guard), 'guard' => $guard];
        }, 3);
        $this->registrar()->forgetCachedPermissions();
        $this->committedAudits->afterCommit($connection, 'rbac.synchronized', actor: $actor, metadata: ['permissions_created' => $result['permissionsCreated'], 'roles_synchronized' => $result['rolesSynchronized'], 'guard' => $result['guard']]);

        return $result;
    }

    /**
     * Synchronize all RBAC contributions through a trusted installation context.
     *
     * @return array<string, mixed>
     */
    public function bootstrap(SystemMutationContext $context): array
    {
        $this->operations->rejectMixedRbacOperation();
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $actor = $this->bootstrapAuthorization->authorize($context, 'nvl.auth.rbac.bootstrap');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = $this->synchronizer->roleConnection();
        $this->registrar()->forgetCachedPermissions();
        $result = $connection->transaction(function () use ($guard): array {
            return ['permissionsCreated' => $this->synchronizer->synchronizePermissions($guard), 'rolesSynchronized' => $this->synchronizer->synchronizeRoles($guard), 'guard' => $guard];
        }, 3);
        $this->registrar()->forgetCachedPermissions();
        $this->committedAudits->afterCommit($connection, 'rbac.bootstrapped', actor: $actor, metadata: [...['permissions_created' => $result['permissionsCreated'], 'roles_synchronized' => $result['rolesSynchronized'], 'guard' => $result['guard']], ...$context->auditMetadata()]);

        return $result;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, displayName: string|null, description: string|null, group: string|null, system: bool, metadata: array<array-key, mixed>}
     */
    private function validateStorePermission(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'displayName', 'description', 'group', 'system', 'metadata']) !== []) {
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
        if (! array_key_exists('group', $data)) {
            $data['group'] = null;
        }
        if (! ($data['group'] === null || is_string($data['group']))) {
            throw new InvalidArgumentException('Invalid Auth input [group].');
        }
        if (! array_key_exists('system', $data)) {
            $data['system'] = false;
        }
        if (! is_bool($data['system'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [system].');
        }
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 160) {
            throw new InvalidArgumentException('Permission names must contain between one and 160 characters.');
        }
        if ($data['displayName'] !== null && mb_strlen($data['displayName']) > 160) {
            throw new InvalidArgumentException('Permission display names must not exceed 160 characters.');
        }
        if ($data['description'] !== null && mb_strlen($data['description']) > 2000) {
            throw new InvalidArgumentException('Permission descriptions must not exceed 2,000 characters.');
        }
        if ($data['group'] !== null && str_contains($data['group'], "\x00")) {
            throw new InvalidArgumentException('Permission groups must not contain null bytes.');
        }
        if ($data['group'] !== null && mb_strlen($data['group']) > 120) {
            throw new InvalidArgumentException('Permission groups must not exceed 120 characters.');
        }
        try {
            $encodedMetadata = json_encode($data['metadata'], JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Permission metadata must be JSON serializable.', previous: $exception);
        }
        if (strlen($encodedMetadata) > 65535) {
            throw new InvalidArgumentException('Permission metadata must not exceed 65,535 encoded bytes.');
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{permissions: list<string>}
     */
    private function validateSyncUserPermissions(array $data): array
    {
        if (array_diff(array_keys($data), ['permissions']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
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
        if (count($data['permissions']) > 250 || count(array_unique($data['permissions'])) !== count($data['permissions'])) {
            throw new InvalidArgumentException('User permissions must be a distinct list containing at most 250 names.');
        }
        foreach ($data['permissions'] as $permission) {
            if (trim($permission) === '' || mb_strlen($permission) > 160) {
                throw new InvalidArgumentException('User permission names must contain between one and 160 characters.');
            }
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, displayName: string|null, description: string|null, group: string|null, system: bool, metadata: array<array-key, mixed>}
     */
    private function validateUpdatePermission(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'displayName', 'description', 'group', 'system', 'metadata']) !== []) {
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
        if (! array_key_exists('group', $data)) {
            $data['group'] = null;
        }
        if (! ($data['group'] === null || is_string($data['group']))) {
            throw new InvalidArgumentException('Invalid Auth input [group].');
        }
        if (! array_key_exists('system', $data)) {
            $data['system'] = false;
        }
        if (! is_bool($data['system'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [system].');
        }
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 160) {
            throw new InvalidArgumentException('Permission names must contain between one and 160 characters.');
        }
        if ($data['displayName'] !== null && mb_strlen($data['displayName']) > 160) {
            throw new InvalidArgumentException('Permission display names must not exceed 160 characters.');
        }
        if ($data['description'] !== null && mb_strlen($data['description']) > 2000) {
            throw new InvalidArgumentException('Permission descriptions must not exceed 2,000 characters.');
        }
        if ($data['group'] !== null && str_contains($data['group'], "\x00")) {
            throw new InvalidArgumentException('Permission groups must not contain null bytes.');
        }
        if ($data['group'] !== null && mb_strlen($data['group']) > 120) {
            throw new InvalidArgumentException('Permission groups must not exceed 120 characters.');
        }
        try {
            $encodedMetadata = json_encode($data['metadata'], JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Permission metadata must be JSON serializable.', previous: $exception);
        }
        if (strlen($encodedMetadata) > 65535) {
            throw new InvalidArgumentException('Permission metadata must not exceed 65,535 encoded bytes.');
        }

        return $data;
    }

    /** Resolve the Spatie permission registrar, which RBAC requires. */
    private function registrar(): PermissionRegistrar
    {
        if (! class_exists(PermissionRegistrar::class)) {
            throw AuthException::invalidConfiguration('RBAC requires spatie/laravel-permission.');
        }

        return $this->rbacContainer->make(PermissionRegistrar::class);
    }
}
