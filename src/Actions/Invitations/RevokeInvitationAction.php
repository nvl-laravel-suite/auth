<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
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
    public function execute(Invitation|string $invitation, Authenticatable $actor): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Revoke);
        $identifier = $invitation instanceof Invitation
            ? $invitation->identifier()
            : $this->identifier($invitation);
        $connection = $invitation instanceof Invitation
            ? $invitation->getConnectionName()
            : (new Invitation)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $identifier): Invitation {
            /** @var Invitation $locked */
            $locked = Invitation::query()->lockForUpdate()->findOrFail($identifier);
            $this->authorization->authorize($actor, 'nvl-auth.invitations.revoke', $locked);

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

    /**
     * Validate an invitation identifier supplied without a model instance.
     */
    private function identifier(string $identifier): string
    {
        if (trim($identifier) === ''
            || $identifier !== trim($identifier)
            || mb_strlen($identifier) > 191
            || preg_match('/[\x00-\x1F\x7F]/', $identifier) === 1) {
            throw new InvalidArgumentException('Invitation identifiers are invalid.');
        }

        return $identifier;
    }
}
