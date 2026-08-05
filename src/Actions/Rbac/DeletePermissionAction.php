<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;

/** Deletes one non-system package permission. */
final readonly class DeletePermissionAction
{
    /** Create the permission deletion use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
        private AuthAuditRecorder $audits,
    ) {}

    /** Delete one permission. */
    public function execute(Authenticatable $actor, Permission|string $permission): bool
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.managePermissions');
        $permission = $this->entities->permission($permission);

        if ($permission->is_system) {
            throw new AuthException('system_permission_delete_forbidden', 'System permissions cannot be deleted.', 422);
        }

        return DB::connection($permission->getConnectionName())->transaction(function () use ($actor, $permission): bool {
            $identifier = $permission->id;
            $deleted = (bool) $permission->delete();
            $this->audits->record('permission.deleted', actor: $actor, metadata: ['permission_id' => $identifier]);
            RbacChanged::dispatch('permission', $identifier, 'deleted');

            return $deleted;
        }, 3);
    }
}
