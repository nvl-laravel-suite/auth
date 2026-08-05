<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Services\RoleHierarchy;
use Nvl\Auth\ValueObjects\RoleData;

/** Updates one package role and its permission assignment. */
final readonly class UpdateRoleAction
{
    /** Create the role update use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
        private RoleHierarchy $hierarchy,
        private AuthAuditRecorder $audits,
    ) {}

    /** Persist one role mutation. */
    public function execute(Authenticatable $actor, Role|string $role, RoleData $data): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        $role = $this->entities->role($role);

        if ($role->is_system && $role->name !== trim($data->name)) {
            throw new AuthException('system_role_immutable', 'System role names cannot be changed.', 422);
        }

        return DB::connection($role->getConnectionName())->transaction(function () use ($actor, $data, $role): Role {
            $parent = $data->parentId !== null ? $this->entities->role($data->parentId) : null;
            $this->hierarchy->assertParentAllowed($role, $parent);
            $role->fill([
                'name' => trim($data->name),
                'display_name' => $data->displayName,
                'description' => $data->description,
                'parent_id' => $parent?->id,
                'priority' => $data->priority,
                'metadata' => $data->metadata,
            ])->save();
            $role->syncPermissions($data->permissions);
            $this->audits->record('role.updated', actor: $actor, metadata: ['role_id' => $role->id]);
            RbacChanged::dispatch('role', $role->id, 'updated');

            return $role->refresh()->load(['parent', 'permissions']);
        }, 3);
    }
}
