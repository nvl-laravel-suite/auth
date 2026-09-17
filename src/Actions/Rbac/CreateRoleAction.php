<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Services\RoleHierarchy;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Services\TenantBoundary;

/** Creates one package role and permission assignment. */
final readonly class CreateRoleAction
{
    /** Create the role creation use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private RbacEntityLocator $entities,
        private RoleHierarchy $hierarchy,
        private AuthConfiguration $configuration,
        private AuthAuditRecorder $audits,
        private TenantBoundary $tenancy,
        private TenantContext $context,
        private TenantMembershipAccess $memberships,
        private MembershipOwnerGuard $owners,
    ) {}

    /** Persist one role. */
    public function execute(Authenticatable $actor, StoreRoleData $data): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        if (config('tenancy.enabled') === true) {
            $this->memberships->assertMember($actor, $this->context->requireTenant());
        }
        $class = $this->models->roleClass();
        $connection = (new $class)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $class, $data): Role {
            if (config('tenancy.enabled') === true) {
                $this->owners->lock($this->context->requireTenant());
            }
            $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
            $parent = $data->parentId !== null ? $this->entities->role($data->parentId) : null;
            /** @var array{tenant_id?: string|null, name: string, guard_name: string, display_name: string|null, description: string|null, parent_id: null, priority: int, is_system: bool, metadata: array<string, mixed>|null} $attributes */
            $attributes = [
                ...(config('tenancy.enabled') === true ? $this->tenancy->attributes('auth.roles') : []),
                'name' => trim($data->name),
                'guard_name' => $guard,
                'display_name' => $data->displayName,
                'description' => $data->description,
                'parent_id' => null,
                'priority' => $data->priority,
                'is_system' => $data->system,
                'metadata' => $data->metadata,
            ];
            $role = $class::query()->create($attributes);
            $this->hierarchy->assertParentAllowed($role, $parent);
            $role->forceFill(['parent_id' => $parent?->id])->save();
            $role->syncPermissions($data->permissions);
            $this->audits->record('role.created', actor: $actor, metadata: ['role_id' => $role->id]);
            RbacChanged::dispatch('role', $role->id, 'created', ['name' => $role->name]);

            return $role->refresh()->load(['parent', 'permissions']);
        }, 3);
    }
}
