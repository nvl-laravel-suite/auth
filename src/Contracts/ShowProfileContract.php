<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\User;

/**
 * Defines the show profile use-case boundary.
 *
 * @api
 */
interface ShowProfileContract
{
    /** Return the authenticated principal. */
    public function execute(Authenticatable $subject): User;
}
