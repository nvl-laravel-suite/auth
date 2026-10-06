<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Defines the link social identity use-case boundary.
 *
 * @api
 */
interface LinkSocialIdentityContract
{
    /**
     * Link or refresh one provider identity.
     */
    public function execute(
        Authenticatable $subject,
        ExternalIdentity $identity,
    ): SocialIdentity;
}
