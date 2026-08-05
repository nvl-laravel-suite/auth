<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\ValueObjects\PermissionData;

/** Creates one package permission. */
final readonly class CreatePermissionAction
{
    /** Create the permission creation use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
        private AuthAuditRecorder $audits,
    ) {}

    /** Persist one permission. */
    public function execute(Authenticatable $actor, PermissionData $data): Permission
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.managePermissions');
        $class = $this->models->permissionClass();
        $connection = (new $class)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $class, $data): Permission {
            $permission = $class::query()->create([
                'name' => trim($data->name),
                'guard_name' => $this->configuration->string('features.rbac.settings.guard', 'web'),
                'display_name' => $data->displayName,
                'description' => $data->description,
                'group' => $data->group,
                'is_system' => $data->system,
                'metadata' => $data->metadata,
            ]);
            $this->audits->record('permission.created', actor: $actor, metadata: ['permission_id' => $permission->id]);
            RbacChanged::dispatch('permission', $permission->id, 'created', ['name' => $permission->name]);

            return $permission->refresh();
        }, 3);
    }
}
