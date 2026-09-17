<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipLocator;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MembershipWriter;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Contracts\TenantContext;

/** Applies one optimistic membership status transition. */
final readonly class SetMembershipStatusAction
{
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private MembershipLocator $memberships,
        private MembershipOwnerGuard $owners,
        private MembershipWriter $writer,
        private TenantContext $context,
        private AuthAuditRecorder $audits,
    ) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, UpdateMembershipStatusData $data): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Update);

        $candidate = $this->memberships->find($membership);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.update', $candidate);

        return DB::connection($candidate->getConnectionName())->transaction(function () use ($actor, $authority, $candidate, $data): TenantMembership {
            $this->owners->lock($this->context->requireTenant());
            $target = $this->memberships->find($candidate, true);
            if ($target->revision !== $data->expectedRevision) {
                throw new AuthException('membership_revision_conflict', 'The membership revision is stale.', 409);
            }
            $this->principals->resolve(new SubjectReference($target->subject_type, $target->subject_id), true);
            if ($data->status !== MembershipStatus::Active) {
                $this->owners->assertCanRemoveOwner($target);
            }
            $updated = $this->writer->setStatus($target, $data->status);
            DB::connection($updated->getConnectionName())->afterCommit(fn () => $this->audits->record(
                'membership.status_changed',
                subject: new SubjectReference($updated->subject_type, $updated->subject_id),
                actor: $actor,
                metadata: ['membership_id' => $updated->identifier(), ...$this->authorization->metadata($authority)],
            ));

            return $updated;
        }, 1);
    }
}
