<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Provisions the first explicitly authorized owner for one tenant. */
final readonly class ProvisionTenantOwnerAction
{
    public function __construct(private MembershipMutator $mutator) {}

    public function execute(SystemMutationContext $authority, SubjectReference $subject): TenantMembership
    {
        return $this->mutator->provisionOwner($authority, $subject);
    }
}
