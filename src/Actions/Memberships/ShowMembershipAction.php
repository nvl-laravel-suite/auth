<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\ShowMembershipContract;
use Nvl\Auth\Data\Display\TenantMembershipData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Membership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\MembershipLocator;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Shows an allowlisted membership and principal projection.
 *
 * @api
 */
final readonly class ShowMembershipAction implements ShowMembershipContract
{
    public function __construct(
        private FeatureGate $features,
        private OwnerMemberships $native,
        private ManagementAuthorizer $authorization,
        private MembershipLocator $memberships,
        private MembershipPrincipalResolver $principals,
    ) {}

    public function execute(Authenticatable $actor, Membership|string $membership): TenantMembershipData
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Read);
        $membership = config('nvl-auth.ownership.scoped') === true ? $this->native->find($membership) : $this->memberships->find($membership);
        $this->authorization->authorize($actor, 'nvl.auth.memberships.view', $membership);
        $principal = $this->principals->resolve(new SubjectReference($membership->subject_type, $membership->subject_id));

        return self::data($membership, $principal instanceof Model ? $principal : null);
    }

    private static function data(Membership $membership, ?Model $principal = null): TenantMembershipData
    {
        return new TenantMembershipData(
            id: $membership->identifier(), tenantId: $membership->tenant_id,
            subjectType: $membership->subject_type, subjectId: $membership->subject_id,
            status: $membership->status, owner: $membership->is_owner, revision: $membership->revision,
            name: is_string($principal?->getAttribute('name')) ? $principal->getAttribute('name') : null,
            email: is_string($principal?->getAttribute('email')) ? $principal->getAttribute('email') : null,
            ownerReference: is_string($membership->getAttribute('owner_reference')) ? OwnerReference::fromJson($membership->getAttribute('owner_reference')) : null,
        );
    }
}
