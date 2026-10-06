<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Results\IssuedApiToken;

/**
 * Defines the rotate api token use-case boundary.
 *
 * @api
 */
interface RotateApiTokenContract
{
    /**
     * Rotate one token and return its replacement secret once.
     */
    public function execute(
        Authenticatable $subject,
        string $tokenId,
        ApiTokenData $data,
    ): IssuedApiToken;
}
