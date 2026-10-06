<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Display\RoleNameAvailabilityData;

/**
 * Defines the check role name availability use-case boundary.
 *
 * @api
 */
interface CheckRoleNameAvailabilityContract
{
    /** Return availability within the configured RBAC guard. */
    public function execute(
        Authenticatable $actor,
        string $name,
        ?string $exceptId = null,
    ): RoleNameAvailabilityData;
}
