<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/**
 * Revokes one invitation as a containment operation.
 */
final readonly class RevokeInvitationAction
{
    /**
     * Create the invitation revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke an invitation idempotently.
     */
    public function execute(Invitation $invitation, Authenticatable $actor): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl-auth.invitations.revoke', $invitation);

        return DB::connection($invitation->getConnectionName())->transaction(function () use ($actor, $invitation): Invitation {
            /** @var Invitation $locked */
            $locked = Invitation::query()->lockForUpdate()->findOrFail($invitation->identifier());

            if ($locked->revoked_at === null && $locked->accepted_at === null) {
                $locked->forceFill([
                    'active_key' => null,
                    'revoked_at' => CarbonImmutable::now(),
                ])->save();
                $this->audits->record(
                    'invitation.revoked',
                    actor: $actor,
                    metadata: ['invitation_id' => $locked->identifier()],
                );
            }

            return $locked;
        }, 3);
    }
}
