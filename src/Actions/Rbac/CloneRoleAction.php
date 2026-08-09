<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;

/** Clones one role's metadata and permission assignment under a new name. */
final readonly class CloneRoleAction
{
    /** Create the role cloning use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private RbacEntityLocator $entities,
        private AuthAuditRecorder $audits,
    ) {}

    /** Clone one role. */
    public function execute(Authenticatable $actor, Role|string $role, string $name, ?string $displayName = null): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        $source = $this->entities->role($role)->load('permissions');
        $class = $this->models->roleClass();

        return DB::connection($source->getConnectionName())->transaction(function () use ($actor, $class, $displayName, $name, $source): Role {
            $clone = $class::query()->create([
                'name' => trim($name),
                'guard_name' => $source->guard_name,
                'display_name' => $displayName,
                'description' => $source->description,
                'parent_id' => $source->parent_id,
                'priority' => $source->priority,
                'is_system' => false,
                'metadata' => $source->metadata,
            ]);
            $clone->syncPermissions($source->permissions);
            $this->audits->record('role.cloned', actor: $actor, metadata: [
                'role_id' => $clone->id,
                'source_role_id' => $source->id,
            ]);
            RbacChanged::dispatch('role', $clone->id, 'cloned', ['source_role_id' => $source->id]);

            return $clone->refresh()->load('permissions');
        }, 3);
    }
}
