<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Models\AuthClient;

/**
 * Defines the list auth clients use-case boundary.
 *
 * @api
 */
interface ListAuthClientsContract
{
    /**
     * Return a bounded client page.
     *
     * @return LengthAwarePaginator<int, AuthClient>
     */
    public function execute(Authenticatable $actor, int $perPage = 25): LengthAwarePaginator;
}
