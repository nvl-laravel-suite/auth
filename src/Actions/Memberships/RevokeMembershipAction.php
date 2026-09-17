<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipLocator;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MembershipWriter;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\TenantMembershipAssignments;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Contracts\TenantContext;

/** Revokes one tenant membership without mutating the global principal. */
final readonly class RevokeMembershipAction
{
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private MembershipLocator $memberships,
        private MembershipOwnerGuard $owners,
        private MembershipWriter $writer,
        private TenantMembershipAssignments $assignments,
        private TenantContext $context,
        private AuthAuditRecorder $audits,
    ) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, int $expectedRevision): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Revoke);

        $candidate = $this->memberships->find($membership);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.revoke', $candidate);

        return DB::connection($candidate->getConnectionName())->transaction(function () use ($actor, $authority, $candidate, $expectedRevision): TenantMembership {
            $tenant = $this->context->requireTenant();
            $this->owners->lock($tenant);
            $target = $this->memberships->find($candidate, true);
            if ($target->revision !== $expectedRevision) {
                throw new AuthException('membership_revision_conflict', 'The membership revision is stale.', 409);
            }
            $this->owners->assertCanRemoveOwner($target);
            $reference = new SubjectReference($target->subject_type, $target->subject_id);
            $principal = $this->principals->resolve($reference, true);
            $this->assignments->sync($principal, [], []);
            PersonalAccessToken::query()->where('tenant_id', $tenant->value)
                ->where('tokenable_type', $target->subject_type)->where('tokenable_id', $target->subject_id)->delete();
            $updated = $this->writer->setStatus($target, MembershipStatus::Revoked);
            DB::connection($updated->getConnectionName())->afterCommit(fn () => $this->audits->record(
                'membership.revoked', subject: $reference, actor: $actor,
                metadata: ['membership_id' => $updated->identifier(), ...$this->authorization->metadata($authority)],
            ));

            return $updated;
        }, 1);
    }
}
