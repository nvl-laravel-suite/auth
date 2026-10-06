<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the revoke recovery codes use-case boundary.
 *
 * @api
 */
interface RevokeRecoveryCodesContract
{
    /**
     * Revoke every active code and return the affected count.
     */
    public function execute(Authenticatable $subject): int;
}
