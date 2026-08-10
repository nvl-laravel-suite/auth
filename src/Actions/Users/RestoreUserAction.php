<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Restores one soft-deleted package principal.
 */
final readonly class RestoreUserAction
{
    /** Create the restoration use case. */
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
        private PrincipalSessionContainment $sessions,
    ) {}

    /** Restore one principal without silently re-enabling it. */
    public function execute(Authenticatable|SystemMutationContext $authority, User|string $user): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.users.restore', $user);
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $user = $this->users->find($user, true);

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $context, $metadata, $user): User {
            $user->restore();
            $this->sessions->contain($user, 'restored', $context);
            $this->audits->record(
                'user.restored',
                subject: SubjectReference::fromAuthenticatable($user),
                actor: $actor,
                metadata: $metadata,
            );
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'restored', $metadata);

            return $user->refresh();
        }, 3);
    }
}
