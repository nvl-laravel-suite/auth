<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Results\RbacSynchronizationResult;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacSynchronizer;
use Spatie\Permission\PermissionRegistrar;

/**
 * Atomically synchronizes the complete contributed Spatie RBAC catalog.
 */
final readonly class SynchronizeRbacAction
{
    /**
     * Create the complete RBAC synchronization use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthConfiguration $configuration,
        private AuthModelRegistry $models,
        private RbacSynchronizer $synchronizer,
        private PermissionRegistrar $registrar,
        private AuthAuditRecorder $audits,
        private AuthOperationBoundary $operations,
    ) {}

    /**
     * Synchronize permission catalogs and role templates in one transaction.
     */
    public function execute(Authenticatable $actor): RbacSynchronizationResult
    {
        $this->operations->rejectMixedRbacOperation();
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $permissionClass = $this->models->permissionClass();
        $connection = (new $permissionClass)->getConnectionName();

        $result = DB::connection($connection)->transaction(function () use ($guard): RbacSynchronizationResult {
            return new RbacSynchronizationResult(
                permissionsCreated: $this->synchronizer->synchronizePermissions($guard),
                rolesSynchronized: $this->synchronizer->synchronizeRoles($guard),
                guard: $guard,
            );
        }, 3);

        $this->registrar->forgetCachedPermissions();
        $this->audits->record(
            'rbac.synchronized',
            actor: $actor,
            metadata: $result->jsonSerialize(),
        );

        return $result;
    }
}
