<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Membership;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;

/** Reloads membership targets through the canonical tenant predicate. */
final readonly class MembershipLocator
{
    public function __construct(private OwnershipBoundary $boundary) {}

    public function find(Membership|string $membership, bool $lock = false): TenantMembership
    {
        $id = $membership instanceof Membership ? $membership->getKey() : $membership;
        if (! is_string($id) || $id === '') {
            throw new AuthException('membership_unavailable', 'The tenant membership is unavailable.', 404);
        }
        $query = $this->boundary->query(TenantMembership::query(), 'auth.memberships')->whereKey($id);
        if ($lock) {
            $query->lockForUpdate();
        }

        return $query->first() ?? throw new AuthException('membership_unavailable', 'The tenant membership is unavailable.', 404);
    }
}
