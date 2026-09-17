<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Provisions the first explicitly authorized owner for one tenant. */
final readonly class ProvisionTenantOwnerAction
{
    public function __construct(private FeatureGate $features, private MembershipMutator $mutator) {}

    public function execute(SystemMutationContext $authority, SubjectReference $subject): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);

        return $this->mutator->provisionOwner($authority, $subject);
    }
}
