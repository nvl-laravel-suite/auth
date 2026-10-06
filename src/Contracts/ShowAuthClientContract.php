<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\AuthClient;

/**
 * Defines the show auth client use-case boundary.
 *
 * @api
 */
interface ShowAuthClientContract
{
    /**
     * Authorize and return one route-resolved client.
     */
    public function execute(Authenticatable $actor, AuthClient $client): AuthClient;
}
