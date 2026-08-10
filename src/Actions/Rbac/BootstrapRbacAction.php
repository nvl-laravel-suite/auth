<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Results\RbacSynchronizationResult;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\RbacSynchronizer;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Spatie\Permission\PermissionRegistrar;

/**
 * Bootstraps RBAC storage without fabricating a privileged human principal.
 */
final readonly class BootstrapRbacAction
{
    /**
     * Create the trusted bootstrap synchronization use case.
     */
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private AuthConfiguration $configuration,
        private AuthModelRegistry $models,
        private RbacSynchronizer $synchronizer,
        private PermissionRegistrar $registrar,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Synchronize all RBAC contributions through a trusted installation context.
     */
    public function execute(SystemMutationContext $context): RbacSynchronizationResult
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $actor = $this->authorization->authorize($context, 'nvl-auth.rbac.bootstrap');
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $permissionClass = $this->models->permissionClass();
        $connection = (new $permissionClass)->getConnectionName();
        $this->registrar->forgetCachedPermissions();

        $result = DB::connection($connection)->transaction(function () use ($guard): RbacSynchronizationResult {
            return new RbacSynchronizationResult(
                permissionsCreated: $this->synchronizer->synchronizePermissions($guard),
                rolesSynchronized: $this->synchronizer->synchronizeRoles($guard),
                guard: $guard,
            );
        }, 3);

        $this->registrar->forgetCachedPermissions();
        $this->audits->record(
            'rbac.bootstrapped',
            actor: $actor,
            metadata: [...$result->jsonSerialize(), ...$context->auditMetadata()],
        );

        return $result;
    }
}
