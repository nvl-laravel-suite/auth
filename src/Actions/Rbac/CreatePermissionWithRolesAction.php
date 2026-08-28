<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacAssignmentService;

/** Creates a permission together with its initial role assignments. */
final readonly class CreatePermissionWithRolesAction
{
    /** Create the permission and role assignment use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
        private RbacAssignmentService $assignments,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Create one permission and attach all resolved roles in one transaction.
     *
     * @param  list<string>  $roleIdentifiers
     */
    public function execute(
        Authenticatable $actor,
        StorePermissionData $data,
        array $roleIdentifiers = [],
    ): Permission {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.managePermissions');

        if ($roleIdentifiers !== []) {
            $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        }

        $class = $this->models->permissionClass();
        $connection = (new $class)->getConnectionName();
        $result = DB::connection($connection)->transaction(function () use ($actor, $class, $data, $roleIdentifiers): array {
            $permission = $class::query()->create([
                'name' => trim($data->name),
                'guard_name' => $this->configuration->string('features.rbac.settings.guard', 'web'),
                'display_name' => $data->displayName,
                'description' => $data->description,
                'group' => PermissionOptionData::normalizeNullableGroup($data->group),
                'is_system' => $data->system,
                'metadata' => $data->metadata,
            ]);

            $result = $this->assignments->attachPermissionToRoles($permission, $roleIdentifiers);
            $this->audits->record('permission.created_with_roles', actor: $actor, metadata: [
                'permission_id' => $result['permission']->id,
                'role_ids' => $result['roleIds'],
                'role_count' => count($result['roleIds']),
            ]);
            RbacChanged::dispatch('permission', $result['permission']->id, 'created', [
                'name' => $result['permission']->name,
                'role_ids' => $result['roleIds'],
                'role_names' => $result['roleNames'],
            ]);

            return $result;
        }, 3);

        $this->assignments->clearPermissionCache();

        return $result['permission'];
    }
}
