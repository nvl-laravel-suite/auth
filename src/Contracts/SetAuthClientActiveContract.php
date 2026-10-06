<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\AuthClient;

/**
 * Defines the set auth client active use-case boundary.
 *
 * @api
 */
interface SetAuthClientActiveContract
{
    /**
     * Set the client state atomically and idempotently.
     */
    public function execute(
        Authenticatable $actor,
        AuthClient $client,
        bool $active,
    ): AuthClient;
}
