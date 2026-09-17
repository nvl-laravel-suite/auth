<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Data\Mutations\EnrollMembershipData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MembershipWriter;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\TenantMembershipAssignments;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Contracts\TenantContext;

/** Enrolls or safely reactivates one tenant membership. */
final readonly class EnrollMembershipAction
{
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private MembershipWriter $writer,
        private MembershipOwnerGuard $owners,
        private TenantMembershipAssignments $assignments,
        private TenantContext $context,
        private AuthAuditRecorder $audits,
    ) {}

    public function execute(Authenticatable|SystemMutationContext $authority, EnrollMembershipData $data): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);

        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.enroll');

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($actor, $authority, $data): TenantMembership {
            $this->owners->lock($this->context->requireTenant());
            $principal = $this->principals->resolve($data->subject, true);
            $membership = $this->writer->enroll($data->subject);
            $this->assignments->sync($principal, $data->roles, $data->permissions);
            DB::connection($membership->getConnectionName())->afterCommit(fn () => $this->audits->record(
                'membership.enrolled', subject: $data->subject, actor: $actor,
                metadata: ['membership_id' => $membership->identifier(), ...$this->authorization->metadata($authority)],
            ));

            return $membership;
        }, 1);
    }
}
