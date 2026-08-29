<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\RbacManager;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Consumes one invitation and optionally applies its Spatie Permission payload.
 */
final readonly class AcceptInvitationAction
{
    /**
     * Create the invitation acceptance use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private RbacManager $rbac,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Consume an invitation for the supplied host subject.
     */
    public function execute(string $token, Authenticatable $subject): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return $this->pipeline->run(
            'invitation_accepted',
            new AuthPipelineContext('invitation_accepted', subject: $reference),
            function () use ($reference, $subject, $token): Invitation {
                $connection = (new Invitation)->getConnectionName();

                return DB::connection($connection)->transaction(function () use ($reference, $subject, $token): Invitation {
                    /** @var Invitation|null $invitation */
                    $invitation = Invitation::query()
                        ->where('token_hash', $this->hasher->hash('invitation-token', $token))
                        ->lockForUpdate()
                        ->first();

                    if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                        throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                    }

                    $roles = is_array($invitation->roles) ? $invitation->roles : [];
                    $permissions = is_array($invitation->permissions) ? $invitation->permissions : [];
                    $this->rbac->assign($subject, $roles, $permissions);
                    $acceptedAt = CarbonImmutable::now();
                    $invitation->forceFill([
                        'active_key' => null,
                        'accepted_by_type' => $reference->type,
                        'accepted_by_id' => $reference->identifier,
                        'accepted_at' => $acceptedAt,
                    ])->save();
                    $this->audits->record(
                        'invitation.accepted',
                        subject: $reference,
                        actor: $subject,
                        metadata: ['invitation_id' => $invitation->identifier()],
                    );
                    InvitationAccepted::dispatch(
                        invitationId: $invitation->identifier(),
                        type: $invitation->type,
                        purpose: $invitation->purpose,
                        subject: $reference,
                        acceptedAt: $invitation->accepted_at,
                    );

                    return $invitation;
                }, 3);
            },
        );
    }
}
