<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StoreClientData;
use Nvl\Auth\Models\AuthClient;

/**
 * Defines the create auth client use-case boundary.
 *
 * @api
 */
interface CreateAuthClientContract
{
    /**
     * Persist a new Auth client.
     */
    public function execute(Authenticatable $actor, StoreClientData $data): AuthClient;
}
