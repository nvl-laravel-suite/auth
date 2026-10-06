<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\StartClientAuthData;
use Nvl\Auth\Results\AuthClientStartResult;

/**
 * Defines the start auth client use-case boundary.
 *
 * @api
 */
interface StartAuthClientContract
{
    /**
     * Resolve an allowlisted return target for an active client.
     */
    public function execute(StartClientAuthData $data): AuthClientStartResult;
}
