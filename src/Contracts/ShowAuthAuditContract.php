<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\AuthAudit;

/**
 * Defines the show auth audit use-case boundary.
 *
 * @api
 */
interface ShowAuthAuditContract
{
    /**
     * Authorize and return one route-resolved audit.
     */
    public function execute(Authenticatable $actor, AuthAudit $audit): AuthAudit;
}
