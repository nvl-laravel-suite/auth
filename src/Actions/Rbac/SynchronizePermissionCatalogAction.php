<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacSynchronizer;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;

/**
 * Synchronizes contributed permission names into Spatie Permission storage.
 */
final readonly class SynchronizePermissionCatalogAction
{
    /**
     * Create the catalog synchronization use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthConfiguration $configuration,
        private RbacSynchronizer $synchronizer,
        private PermissionRegistrar $registrar,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Create missing permissions without deleting host-owned records.
     */
    public function execute(Authenticatable $actor): int
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new Permission)->getConnectionName();
        $created = DB::connection($connection)->transaction(
            fn (): int => $this->synchronizer->synchronizePermissions($guard),
            3,
        );

        $this->registrar->forgetCachedPermissions();
        $this->audits->record(
            'rbac.permissions_synchronized',
            actor: $actor,
            metadata: ['created' => $created, 'guard' => $guard],
        );

        return $created;
    }
}
