<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Data\Display\TenantMembershipData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\MembershipLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Shows an allowlisted membership and principal projection. */
final readonly class ShowMembershipAction
{
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private MembershipLocator $memberships,
        private MembershipPrincipalResolver $principals,
    ) {}

    public function execute(Authenticatable $actor, TenantMembership|string $membership): TenantMembershipData
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Read);
        $membership = $this->memberships->find($membership);
        $this->authorization->authorize($actor, 'nvl-auth.memberships.view', $membership);
        $principal = $this->principals->resolve(new SubjectReference($membership->subject_type, $membership->subject_id));

        return self::data($membership, $principal instanceof Model ? $principal : null);
    }

    private static function data(TenantMembership $membership, ?Model $principal = null): TenantMembershipData
    {
        return new TenantMembershipData(
            id: $membership->identifier(), tenantId: $membership->tenant_id,
            subjectType: $membership->subject_type, subjectId: $membership->subject_id,
            status: $membership->status, owner: $membership->is_owner, revision: $membership->revision,
            name: is_string($principal?->getAttribute('name')) ? $principal->getAttribute('name') : null,
            email: is_string($principal?->getAttribute('email')) ? $principal->getAttribute('email') : null,
        );
    }
}
