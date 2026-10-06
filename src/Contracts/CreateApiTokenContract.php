<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Results\IssuedApiToken;

/**
 * Defines the create api token use-case boundary.
 *
 * @api
 */
interface CreateApiTokenContract
{
    /**
     * Issue one token directly through the configured provider.
     */
    public function execute(Authenticatable $subject, ApiTokenData $data): IssuedApiToken;
}
