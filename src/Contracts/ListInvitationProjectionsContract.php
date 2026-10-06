<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;

/**
 * Defines the list invitation projections use-case boundary.
 *
 * @api
 */
interface ListInvitationProjectionsContract
{
    /**
     * Return a bounded page of value-only invitation state.
     *
     * @return LengthAwarePaginator<int, InvitationReadData>
     */
    public function execute(
        Authenticatable $actor,
        ?InvitationIndexQueryData $filters = null,
        int $perPage = 25,
    ): LengthAwarePaginator;
}
