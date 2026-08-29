<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Results\IssuedInvitation;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationDeliveryMetadataPolicy;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\OpaqueTokenFactory;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;

/**
 * Rotates and republishes one still-active invitation token.
 */
final readonly class ResendInvitationAction
{
    /**
     * Create the invitation resend use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private OpaqueTokenFactory $tokens,
        private SecretHasher $hasher,
        private ManagementAuthorizer $authorization,
        private AuthAuditRecorder $audits,
        private ?InvitationDeliveryMetadataPolicy $deliveryMetadata = null,
    ) {}

    /**
     * Resend one invitation with a newly rotated token.
     */
    public function execute(
        Invitation $invitation,
        ?Authenticatable $actor = null,
        ?string $locale = null,
        ?InvitationIssuanceContext $context = null,
    ): IssuedInvitation {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Issue);
        $context ??= new InvitationIssuanceContext;

        if ($actor instanceof Authenticatable) {
            $this->authorization->authorize($actor, 'nvl-auth.invitations.resend', $invitation);
        } elseif (! $context->actorlessAuthorized) {
            throw new AuthException('forbidden', 'Actorless invitation resend was not explicitly authorized.', 403);
        }
        $connection = $invitation->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $context, $invitation, $locale): IssuedInvitation {
            /** @var Invitation $locked */
            $locked = Invitation::query()->lockForUpdate()->findOrFail($invitation->identifier());

            if (! $locked->isUsable()) {
                throw new AuthException('invitation_unavailable', 'The invitation is no longer active.', 410);
            }

            $cooldown = $this->configuration->integerBetween(
                'features.invitations.settings.resend_cooldown_seconds',
                60,
                1,
                86_400,
            );

            if ($locked->last_sent_at?->addSeconds($cooldown)->isFuture()) {
                throw new AuthException('invitation_resend_limited', 'The invitation was sent too recently.', 429);
            }

            $token = $this->tokens->make();
            $locked->forceFill([
                'token_hash' => $this->hasher->hash('invitation-token', $token),
                'resend_count' => $locked->resend_count + 1,
                'last_sent_at' => CarbonImmutable::now(),
                'expires_at' => $context->expiresAt ?? $locked->expires_at,
            ])->save();
            AuthDeliveryRequested::dispatch(new AuthDeliveryRequest(
                messageId: (string) Str::uuid(),
                feature: AuthFeature::Invitations,
                type: AuthMessageType::Invitation,
                recipient: $locked->recipient,
                payload: [
                    'invitation_id' => $locked->identifier(),
                    'token' => $token,
                    'type' => $locked->type,
                    'purpose' => $locked->purpose,
                    'return_path' => $context->returnPath ?? (
                        is_array($locked->metadata) ? ($locked->metadata['return_path'] ?? null) : null
                    ),
                ],
                expiresAt: $locked->expires_at,
                locale: $locale,
                metadata: ['invitation_id' => $locked->identifier(), 'resend' => true],
                invitation: ($this->deliveryMetadata ?? new InvitationDeliveryMetadataPolicy(
                    $this->configuration,
                ))->deliveryData($locked),
            ));
            $this->audits->record(
                'invitation.resent',
                actor: $actor,
                metadata: ['invitation_id' => $locked->identifier()],
            );

            return new IssuedInvitation($locked, $token);
        }, 3);
    }
}
