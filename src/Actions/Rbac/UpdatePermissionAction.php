<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\UpdatePermissionContract;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Data\Mutations\UpdatePermissionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Support\Events\DomainEventDispatcher;

/**
 * Updates one package permission.
 *
 * @api
 */
final readonly class UpdatePermissionAction implements UpdatePermissionContract
{
    /** Create the permission update use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
        private AuthAuditRecorder $audits,
        private AuthOperationBoundary $operations,
        private DomainEventDispatcher $domainEvents,
    ) {}

    /** Persist one permission mutation. */
    public function execute(Authenticatable $actor, Permission|string $permission, UpdatePermissionData $data): Permission
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->operations->requirePlatformAdministration();
        $this->authorization->authorize($actor, 'nvl.auth.rbac.managePermissions');
        $permission = $this->entities->permission($permission);

        if ($permission->is_system && $permission->name !== trim($data->name)) {
            throw new AuthException('system_permission_immutable', 'System permission names cannot be changed.', 422);
        }

        return DB::connection($permission->getConnectionName())->transaction(function () use ($actor, $data, $permission): Permission {
            $permission->fill([
                'name' => trim($data->name),
                'display_name' => $data->displayName,
                'description' => $data->description,
                'group' => PermissionOptionData::normalizeNullableGroup($data->group),
                'metadata' => $data->metadata,
            ])->save();
            $this->audits->record('permission.updated', actor: $actor, metadata: ['permission_id' => $permission->id]);
            $this->domainEvents->dispatch(new RbacChanged('permission', $permission->id, 'updated'), $permission->getConnection());

            return $permission->refresh();
        }, 3);
    }
}
