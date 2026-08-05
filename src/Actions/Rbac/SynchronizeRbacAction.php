<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacSynchronizer;
use Spatie\Permission\Models\Permission;
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
        private RbacSynchronizer $synchronizer,
        private PermissionRegistrar $registrar,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Synchronize permission catalogs and role templates in one transaction.
     *
     * @return array{permissions_created: int, roles_synchronized: int}
     */
    public function execute(Authenticatable $actor): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new Permission)->getConnectionName();

        $result = DB::connection($connection)->transaction(function () use ($guard): array {
            return [
                'permissions_created' => $this->synchronizer->synchronizePermissions($guard),
                'roles_synchronized' => $this->synchronizer->synchronizeRoles($guard),
            ];
        }, 3);

        $this->registrar->forgetCachedPermissions();
        $this->audits->record(
            'rbac.synchronized',
            actor: $actor,
            metadata: [...$result, 'guard' => $guard],
        );

        return $result;
    }
}
