<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\SocialIdentity;

/**
 * Defines the revoke social identity use-case boundary.
 *
 * @api
 */
interface RevokeSocialIdentityContract
{
    /**
     * Revoke an owned identity idempotently.
     */
    public function execute(
        Authenticatable $subject,
        SocialIdentity $identity,
    ): SocialIdentity;
}
