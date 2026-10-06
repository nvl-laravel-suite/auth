<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the revoke api token use-case boundary.
 *
 * @api
 */
interface RevokeApiTokenContract
{
    /**
     * Revoke one token idempotently.
     */
    public function execute(Authenticatable $subject, string $tokenId): bool;
}
