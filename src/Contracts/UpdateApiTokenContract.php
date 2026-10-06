<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Defines the update api token use-case boundary.
 *
 * @api
 */
interface UpdateApiTokenContract
{
    /**
     * Update one subject-owned token.
     */
    public function execute(
        Authenticatable $subject,
        string $tokenId,
        ApiTokenData $data,
    ): ApiTokenSnapshot;
}
