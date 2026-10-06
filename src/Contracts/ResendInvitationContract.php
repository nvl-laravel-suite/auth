<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Results\IssuedInvitation;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;

/**
 * Defines the resend invitation use-case boundary.
 *
 * @api
 */
interface ResendInvitationContract
{
    /**
     * Resend one invitation with a newly rotated token.
     */
    public function execute(
        Invitation|string $invitation,
        ?Authenticatable $actor = null,
        ?string $locale = null,
        ?InvitationIssuanceContext $context = null,
    ): IssuedInvitation;
}
