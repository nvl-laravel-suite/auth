<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateClientData;
use Nvl\Auth\Models\AuthClient;

/**
 * Defines the update auth client use-case boundary.
 *
 * @api
 */
interface UpdateAuthClientContract
{
    /**
     * Update a client atomically.
     */
    public function execute(
        Authenticatable $actor,
        AuthClient $client,
        UpdateClientData $data,
    ): AuthClient;
}
