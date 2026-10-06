<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Results\RbacAnalytics;

/**
 * Defines the show rbac analytics use-case boundary.
 *
 * @api
 */
interface ShowRbacAnalyticsContract
{
    /** Return current package RBAC aggregates. */
    public function execute(Authenticatable $actor): RbacAnalytics;
}
