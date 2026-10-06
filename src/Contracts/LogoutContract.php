<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/**
 * Defines the logout use-case boundary.
 *
 * @api
 */
interface LogoutContract
{
    /**
     * Log out and rotate the session CSRF state.
     */
    public function execute(): void;
}
