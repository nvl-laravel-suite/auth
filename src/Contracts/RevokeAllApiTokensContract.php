<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the revoke all api tokens use-case boundary.
 *
 * @api
 */
interface RevokeAllApiTokensContract
{
    /**
     * Revoke all tokens and return the affected count.
     */
    public function execute(Authenticatable $subject): int;
}
