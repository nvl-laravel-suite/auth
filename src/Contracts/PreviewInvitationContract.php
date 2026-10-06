<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Models\Invitation;

/**
 * Defines the preview invitation use-case boundary.
 *
 * @api
 */
interface PreviewInvitationContract
{
    /**
     * Resolve one active invitation by its bearer token.
     */
    public function execute(string $token): Invitation;
}
