<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Services\TenantBoundary;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Serializes and protects tenant owner lifecycle transitions. */
final readonly class MembershipOwnerGuard
{
    public function __construct(private TenantBoundary $boundary) {}

    public function lock(TenantId $tenant): void
    {
        $lock = $this->boundary->query(TenantMembershipLock::query(), 'auth.membership_locks')
            ->where('tenant_id', $tenant->value)->lockForUpdate()->first();
        if (! $lock instanceof TenantMembershipLock) {
            throw AuthException::invalidConfiguration('The tenant membership lock is missing.');
        }
    }

    public function assertCanRemoveOwner(TenantMembership $membership): void
    {
        if ($membership->is_owner && $membership->status === MembershipStatus::Active
            && $this->boundary->query(TenantMembership::query(), 'auth.memberships')
                ->where('status', MembershipStatus::Active->value)->where('is_owner', true)->count() <= 1) {
            throw new AuthException('membership_last_owner', 'The last active tenant owner cannot be removed.', 409);
        }
    }

    public function assertPrincipalCanBeDisabled(SubjectReference $subject): void
    {
        $owners = TenantMembership::query()->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)
            ->where('status', MembershipStatus::Active->value)->where('is_owner', true)->orderBy('tenant_id')->get();
        foreach ($owners as $owner) {
            $tenant = new TenantId($owner->tenant_id);
            $lock = TenantMembershipLock::query()->where('tenant_id', $tenant->value)->lockForUpdate()->first();
            if (! $lock instanceof TenantMembershipLock) {
                throw AuthException::invalidConfiguration('The tenant membership lock is missing.');
            }
            if (TenantMembership::query()->where('tenant_id', $tenant->value)->where('status', MembershipStatus::Active->value)
                ->where('is_owner', true)->count() <= 1) {
                throw new AuthException('membership_last_owner', 'The principal retains last-owner responsibility.', 409);
            }
        }
    }
}
