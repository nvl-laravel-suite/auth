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
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacAssignmentService;

/** Adds permissions to a role without replacing existing assignments. */
final readonly class AddRolePermissionsAction
{
    /** Create the additive role permission use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacAssignmentService $assignments,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Add a bounded set of permission IDs or names atomically.
     *
     * @param  list<string>  $permissionIdentifiers
     */
    public function execute(
        Authenticatable $actor,
        Role|string $role,
        array $permissionIdentifiers,
    ): Role {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        $result = DB::connection($this->assignments->roleConnectionName($role))->transaction(
            function () use ($actor, $permissionIdentifiers, $role): array {
                $result = $this->assignments->add($role, $permissionIdentifiers);
                $this->audits->record('role.permissions_added', actor: $actor, metadata: [
                    'role_id' => $result['role']->id,
                    'permission_ids' => $result['permissionIds'],
                    'permission_count' => count($result['permissionIds']),
                ]);
                RbacChanged::dispatch('role', $result['role']->id, 'permissions_added', [
                    'permission_ids' => $result['permissionIds'],
                    'permission_names' => $result['permissionNames'],
                ]);

                return $result;
            },
            3,
        );

        $this->assignments->clearPermissionCache();

        return $result['role'];
    }
}
