<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\EnrollMembershipData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Enrolls or safely reactivates one tenant membership. */
final readonly class EnrollMembershipAction
{
    public function __construct(private FeatureGate $features, private MembershipMutator $mutator) {}

    public function execute(Authenticatable|SystemMutationContext $authority, EnrollMembershipData $data): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);

        return $this->mutator->enroll($authority, $data);
    }
}
