<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\User;

/**
 * Defines the show user use-case boundary.
 *
 * @api
 */
interface ShowUserContract
{
    /** Return one principal. */
    public function execute(Authenticatable $actor, User|string $user): User;
}
