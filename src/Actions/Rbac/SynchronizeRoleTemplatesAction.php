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
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

/**
 * Creates or updates contributed role templates in Spatie Permission storage.
 */
final readonly class SynchronizeRoleTemplatesAction
{
    /**
     * Create the role-template synchronization use case.
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
     * Synchronize every configured role template and return the role count.
     */
    public function execute(Authenticatable $actor): int
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.synchronize');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new Role)->getConnectionName();
        $roleCount = DB::connection($connection)->transaction(
            fn (): int => $this->synchronizer->synchronizeRoles($guard),
            3,
        );

        $this->registrar->forgetCachedPermissions();
        $this->audits->record(
            'rbac.roles_synchronized',
            actor: $actor,
            metadata: ['roles' => $roleCount, 'guard' => $guard],
        );

        return $roleCount;
    }
}
