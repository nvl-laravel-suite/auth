<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Enums\MembershipStatus;

/**
 * Defines the list own memberships use-case boundary.
 *
 * @api
 */
interface ListOwnMembershipsContract
{
    /** @return Collection<int, covariant array{tenant_id: string, membership_id: string, status: 'active'|'suspended'|'revoked', revision: int}|array{owner: array{version: int, type: string, storage: string, keyType: string, key: string}, membership_id: string, status: MembershipStatus, revision: int}> */
    public function execute(Authenticatable $subject): Collection;
}
