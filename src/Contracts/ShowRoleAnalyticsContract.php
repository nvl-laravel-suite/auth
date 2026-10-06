<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Display\RoleAnalyticsData;
use Nvl\Auth\Models\Role;

/**
 * Defines the show role analytics use-case boundary.
 *
 * @api
 */
interface ShowRoleAnalyticsContract
{
    /** Calculate current aggregates without loading related identities. */
    public function execute(Authenticatable $actor, Role|string $role): RoleAnalyticsData;
}
