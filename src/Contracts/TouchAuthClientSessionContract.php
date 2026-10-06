<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Models\AuthClientSession;

/**
 * Defines the touch auth client session use-case boundary.
 *
 * @api
 */
interface TouchAuthClientSessionContract
{
    /**
     * Touch one active correlation by its host session identifier.
     */
    public function execute(string $clientId, string $sessionId): AuthClientSession;
}
