<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Lists the authenticated global identity's own minimal active tenant projections. */
final readonly class ListOwnMembershipsAction
{
    public function __construct(private FeatureGate $features, private AuthOperationBoundary $operations) {}

    /** @return Collection<int, array{tenant_id: string, membership_id: string, status: string, revision: int}> */
    public function execute(Authenticatable $subject): Collection
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Read);
        $this->operations->central(AuthIdentityOperation::MembershipDiscovery, $subject);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return TenantMembership::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)
            ->where('status', MembershipStatus::Active->value)->orderBy('tenant_id')->get()
            ->map(static fn (TenantMembership $membership): array => [
                'tenant_id' => $membership->tenant_id,
                'membership_id' => $membership->identifier(),
                'status' => $membership->status->value,
                'revision' => $membership->revision,
            ]);
    }
}
