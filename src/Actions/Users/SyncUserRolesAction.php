<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\RbacManager;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Replaces one principal's direct role assignment.
 */
final readonly class SyncUserRolesAction
{
    /** Create the role assignment use case. */
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private RbacPrincipalAccess $principals,
        private RbacManager $rbac,
        private AuthAuditRecorder $audits,
    ) {}

    /** Synchronize one validated role assignment atomically. */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        Authenticatable|string $user,
        SyncUserRolesData $data,
    ): Authenticatable {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.users.manageAccess', $user);
        $metadata = $this->authorization->metadata($authority);
        $user = $this->principals->find($user);

        return DB::connection($this->principals->connectionName($user))->transaction(function () use ($actor, $data, $metadata, $user): Authenticatable {
            $this->rbac->syncRoles($user, $data->roles, $metadata);
            $this->audits->record('user.roles_synchronized', subject: SubjectReference::fromAuthenticatable($user), actor: $actor, metadata: [
                'roles' => $data->roles,
                ...$metadata,
            ]);

            return $this->rbac->refresh($user, ['roles']);
        }, 3);
    }
}
