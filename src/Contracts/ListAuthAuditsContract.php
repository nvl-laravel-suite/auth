<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Models\AuthAudit;

/**
 * Defines the list auth audits use-case boundary.
 *
 * @api
 */
interface ListAuthAuditsContract
{
    /**
     * Return a bounded audit page.
     *
     * @return LengthAwarePaginator<int, AuthAudit>
     */
    public function execute(Authenticatable $actor, int $perPage = 50): LengthAwarePaginator;
}
