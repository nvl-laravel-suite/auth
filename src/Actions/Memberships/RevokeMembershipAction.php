<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Revokes one tenant membership without mutating the global principal. */
final readonly class RevokeMembershipAction
{
    public function __construct(private FeatureGate $features, private MembershipMutator $mutator) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, int $expectedRevision): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Revoke);

        return $this->mutator->revoke($authority, $membership, $expectedRevision);
    }
}
