<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\AuthClient;

/**
 * Defines the delete auth client use-case boundary.
 *
 * @api
 */
interface DeleteAuthClientContract
{
    /**
     * Delete a client and its correlation rows.
     */
    public function execute(Authenticatable $actor, AuthClient $client): void;
}
