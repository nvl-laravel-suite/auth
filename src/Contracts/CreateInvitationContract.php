<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Results\IssuedInvitation;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;

/**
 * Defines the create invitation use-case boundary.
 *
 * @api
 */
interface CreateInvitationContract
{
    /**
     * Issue one invitation.
     */
    public function execute(
        StoreInvitationData $data,
        ?Authenticatable $actor = null,
        ?InvitationIssuanceContext $context = null,
    ): IssuedInvitation;
}
