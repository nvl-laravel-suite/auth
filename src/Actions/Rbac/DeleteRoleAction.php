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

/** Deletes one non-system package role. */
final readonly class DeleteRoleAction
{
    /** Create the role deletion use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
        private AuthAuditRecorder $audits,
    ) {}

    /** Delete one role. */
    public function execute(Authenticatable $actor, Role|string $role): bool
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        $role = $this->entities->role($role);

        if ($role->is_system) {
            throw new AuthException('system_role_delete_forbidden', 'System roles cannot be deleted.', 422);
        }

        return DB::connection($role->getConnectionName())->transaction(function () use ($actor, $role): bool {
            $identifier = $role->id;
            $deleted = (bool) $role->delete();
            $this->audits->record('role.deleted', actor: $actor, metadata: ['role_id' => $identifier]);
            RbacChanged::dispatch('role', $identifier, 'deleted');

            return $deleted;
        }, 3);
    }
}
