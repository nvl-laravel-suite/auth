<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Display\TotpSecurityStateData;

/**
 * Reads the authenticated principal's TOTP lifecycle without provisioning material.
 *
 * @api
 */
interface ShowTotpSecurityStateContract
{
    /** Return lifecycle counts for the host-authorized authenticated principal. */
    public function execute(Authenticatable $subject): TotpSecurityStateData;
}
