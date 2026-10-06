<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Results\InvitationRegistrationResult;

/**
 * Defines the register invitation use-case boundary.
 *
 * @api
 */
interface RegisterInvitationContract
{
    /** Register the invited subject and return the consumed invitation and subject. */
    public function execute(
        AcceptInvitationData $data,
        ?Authenticatable $authenticatedRecipient = null,
    ): InvitationRegistrationResult;
}
