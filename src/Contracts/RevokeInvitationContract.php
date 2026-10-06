<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Invitation;

/**
 * Defines the revoke invitation use-case boundary.
 *
 * @api
 */
interface RevokeInvitationContract
{
    /**
     * Revoke an invitation idempotently.
     */
    public function execute(Invitation|string $invitation, Authenticatable $actor): Invitation;
}
