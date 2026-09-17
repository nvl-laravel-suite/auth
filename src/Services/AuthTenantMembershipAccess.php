<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Enums\TenantStatus;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Revalidates persisted active membership without trusting a cache or Gate. */
final readonly class AuthTenantMembershipAccess implements TenantMembershipAccess
{
    public function __construct(private TenantDirectory $directory, private MembershipPrincipalResolver $principals) {}

    public function assertMember(Authenticatable $actor, TenantId $tenant): void
    {
        $descriptor = $this->directory->find($tenant);
        $this->principals->assertEligible($actor);
        $subject = SubjectReference::fromAuthenticatable($actor);
        if ($descriptor->status !== TenantStatus::Active
            || ! TenantMembership::query()
                ->where('tenant_id', $tenant->value)
                ->where('subject_type', $subject->type)
                ->where('subject_id', $subject->identifier)
                ->where('status', MembershipStatus::Active->value)
                ->exists()) {
            throw new AuthException('tenant_membership_required', 'An active tenant membership is required.', 403);
        }
    }
}
