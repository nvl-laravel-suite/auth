<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Models\AuthClientSession;

/**
 * Defines the end auth client session use-case boundary.
 *
 * @api
 */
interface EndAuthClientSessionContract
{
    /**
     * End one client-session record idempotently.
     */
    public function execute(AuthClientSession $session, string $reason = 'logout'): AuthClientSession;
}
