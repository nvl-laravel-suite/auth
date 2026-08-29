<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Illuminate\Contracts\Auth\Authenticatable;
use InvalidArgumentException;
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationDeliveryMetadataPolicy;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;

/**
 * Finds one active invitation through an explicitly trusted read boundary.
 */
final readonly class FindActiveInvitationAction
{
    /**
     * Create the active invitation lookup use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private SecretHasher $hasher,
        private InvitationDeliveryMetadataPolicy $deliveryMetadata,
    ) {}

    /**
     * Find the newest active invitation matching normalized trusted input.
     *
     * @param  list<string>|null  $types
     */
    public function execute(
        string $recipient,
        string $purpose,
        ?array $types = null,
        ?string $context = null,
        ?Authenticatable $actor = null,
        ?InvitationIssuanceContext $issuance = null,
    ): ?InvitationReadData {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);

        if ($actor instanceof Authenticatable) {
            $this->authorization->authorize($actor, 'nvl-auth.invitations.viewAny');
        } elseif ($issuance?->actorlessAuthorized !== true) {
            throw new AuthException(
                'forbidden',
                'Actorless invitation lookup was not explicitly authorized.',
                403,
            );
        }

        $recipient = mb_strtolower(trim($recipient));
        $purpose = trim($purpose);
        $context = $context === null ? null : trim($context);

        if ($recipient === '' || mb_strlen($recipient) > 320) {
            throw new InvalidArgumentException('Invitation recipients must contain between one and 320 characters.');
        }

        if ($purpose === '' || mb_strlen($purpose) > 120) {
            throw new InvalidArgumentException('Invitation purposes must contain between one and 120 characters.');
        }

        if ($context !== null && ($context === '' || mb_strlen($context) > 191)) {
            throw new InvalidArgumentException('Invitation contexts must contain between one and 191 characters.');
        }

        $filters = new InvitationIndexQueryData(types: $types);
        $invitation = Invitation::query()
            ->where('recipient_hash', $this->hasher->hash('invitation-recipient', $recipient))
            ->where('purpose', $purpose)
            ->whereNull('accepted_at')
            ->whereNull('revoked_at')
            ->where('expires_at', '>', now())
            ->when($filters->types !== null, fn ($query) => $query->whereIn('type', $filters->types))
            ->when($context !== null, fn ($query) => $query->where(
                'context_hash',
                $this->hasher->hash('invitation-context', (string) $context),
            ))
            ->latest('created_at')
            ->orderByDesc('id')
            ->first();

        if (! $invitation instanceof Invitation) {
            return null;
        }

        return InvitationReadData::fromModel(
            $invitation,
            $this->deliveryMetadata->deliveryData($invitation),
        );
    }
}
