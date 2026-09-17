<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MembershipWriter;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Contracts\TenantContext;

/** Provisions the first explicitly authorized owner for one tenant. */
final readonly class ProvisionTenantOwnerAction
{
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private MembershipOwnerGuard $owners,
        private MembershipWriter $writer,
        private TenantContext $context,
        private AuthAuditRecorder $audits,
    ) {}

    public function execute(SystemMutationContext $authority, SubjectReference $subject): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);

        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.enroll');

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($actor, $authority, $subject): TenantMembership {
            $tenant = $this->context->requireTenant();
            TenantMembershipLock::query()->firstOrCreate(['tenant_id' => $tenant->value]);
            $this->owners->lock($tenant);
            $this->principals->resolve($subject, true);
            $membership = $this->writer->enroll($subject);
            if (! $membership->is_owner) {
                $membership->forceFill(['is_owner' => true, 'status' => MembershipStatus::Active, 'revision' => $membership->revision + 1])->save();
            }
            $membership = $membership->refresh();
            DB::connection($membership->getConnectionName())->afterCommit(fn () => $this->audits->record(
                'membership.owner_provisioned', subject: $subject, actor: $actor,
                metadata: ['membership_id' => $membership->identifier(), ...$this->authorization->metadata($authority)],
            ));

            return $membership;
        }, 1);
    }
}
