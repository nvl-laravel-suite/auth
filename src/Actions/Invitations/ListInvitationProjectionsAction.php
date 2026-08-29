<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationDeliveryMetadataPolicy;

/**
 * Orchestrates the canonical invitation listing Action into value-only projections.
 */
final readonly class ListInvitationProjectionsAction
{
    /**
     * Create the invitation projection listing use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ListInvitationsAction $invitations,
        private InvitationDeliveryMetadataPolicy $deliveryMetadata,
    ) {}

    /**
     * Return a bounded page of value-only invitation state.
     *
     * @return LengthAwarePaginator<int, InvitationReadData>
     */
    public function execute(
        Authenticatable $actor,
        ?InvitationIndexQueryData $filters = null,
        int $perPage = 25,
    ): LengthAwarePaginator {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);

        return $this->invitations
            ->execute($actor, $filters, $perPage)
            ->through(fn (Invitation $invitation): InvitationReadData => InvitationReadData::fromModel(
                $invitation,
                $this->deliveryMetadata->deliveryData($invitation),
            ));
    }
}
