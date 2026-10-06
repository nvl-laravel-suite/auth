<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Invitation;

/**
 * Defines the accept invitation use-case boundary.
 *
 * @api
 */
interface AcceptInvitationContract
{
    /**
     * Consume an invitation for the supplied host subject.
     */
    public function execute(string $token, Authenticatable $subject): Invitation;
}
