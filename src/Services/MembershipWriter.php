<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Services\TenantBoundary;

/** Performs transaction-owned membership persistence without public Action chaining. */
final readonly class MembershipWriter
{
    public function __construct(private TenantContext $context, private TenantBoundary $boundary) {}

    public function enroll(SubjectReference $subject): TenantMembership
    {
        $this->assertTransaction();
        $tenant = $this->context->requireTenant();
        $membership = $this->boundary->query(TenantMembership::query(), 'auth.memberships')
            ->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)->lockForUpdate()->first();
        if ($membership instanceof TenantMembership) {
            if ($membership->status === MembershipStatus::Revoked) {
                $membership->forceFill(['status' => MembershipStatus::Active, 'is_owner' => false, 'revision' => $membership->revision + 1])->save();
            }

            return $membership->refresh();
        }

        return TenantMembership::query()->create([
            ...$this->boundary->attributes('auth.memberships'),
            'tenant_id' => $tenant->value,
            'subject_type' => $subject->type,
            'subject_id' => $subject->identifier,
            'status' => MembershipStatus::Active,
            'is_owner' => false,
            'revision' => 1,
        ]);
    }

    public function setStatus(TenantMembership $membership, MembershipStatus $status): TenantMembership
    {
        $this->assertTransaction();
        if ($membership->status !== $status) {
            $membership->forceFill(['status' => $status, 'revision' => $membership->revision + 1])->save();
        }

        return $membership->refresh();
    }

    private function assertTransaction(): void
    {
        if (TenantMembership::query()->getConnection()->transactionLevel() < 1) {
            throw AuthException::invalidConfiguration('Membership writes require their owning transaction.');
        }
    }
}
