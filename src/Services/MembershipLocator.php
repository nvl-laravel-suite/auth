<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Tenancy\Services\TenantBoundary;

/** Reloads membership targets through the canonical tenant predicate. */
final readonly class MembershipLocator
{
    public function __construct(private TenantBoundary $boundary) {}

    public function find(TenantMembership|string $membership, bool $lock = false): TenantMembership
    {
        $id = $membership instanceof TenantMembership ? $membership->getKey() : $membership;
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
