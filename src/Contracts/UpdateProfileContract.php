<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Models\User;

/**
 * Defines the update profile use-case boundary.
 *
 * @api
 */
interface UpdateProfileContract
{
    /** Persist self-service profile changes. */
    public function execute(Authenticatable $subject, UpdateProfileData $data): User;
}
