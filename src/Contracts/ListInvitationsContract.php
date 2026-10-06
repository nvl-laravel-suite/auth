<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Models\Invitation;

/**
 * Defines the list invitations use-case boundary.
 *
 * @api
 */
interface ListInvitationsContract
{
    /**
     * Return a bounded invitation page.
     *
     * @return LengthAwarePaginator<int, Invitation>
     */
    public function execute(
        Authenticatable $actor,
        ?InvitationIndexQueryData $filters = null,
        int $perPage = 25,
    ): LengthAwarePaginator;
}
