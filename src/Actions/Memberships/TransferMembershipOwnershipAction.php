<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MembershipLocator;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Contracts\TenantContext;

/** Transfers tenant ownership inside one locked transaction. */
final readonly class TransferMembershipOwnershipAction
{
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private MembershipLocator $memberships,
        private MembershipOwnerGuard $owners,
        private TenantContext $context,
        private AuthAuditRecorder $audits,
    ) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, TransferMembershipOwnershipData $data): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Update);

        $candidate = $this->memberships->find($membership);
        $recipientCandidate = $this->memberships->find($data->recipientMembershipId);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.transferOwnership', $candidate);

        return DB::connection($candidate->getConnectionName())->transaction(function () use ($actor, $authority, $candidate, $data, $recipientCandidate): TenantMembership {
            $this->owners->lock($this->context->requireTenant());
            $identifiers = [$candidate->identifier(), $recipientCandidate->identifier()];
            sort($identifiers, SORT_STRING);
            $locked = [];
            foreach ($identifiers as $identifier) {
                $locked[$identifier] = $this->memberships->find($identifier, true);
            }
            $source = $locked[$candidate->identifier()];
            $recipient = $locked[$recipientCandidate->identifier()];
            if ($source->revision !== $data->expectedRevision) {
                throw new AuthException('membership_revision_conflict', 'The membership revision is stale.', 409);
            }
            if (! $source->is_owner || $source->status !== MembershipStatus::Active || $source->is($recipient)) {
                throw new AuthException('membership_ownership_invalid', 'Membership ownership cannot be transferred.', 422);
            }
            $this->principals->resolve(new SubjectReference($recipient->subject_type, $recipient->subject_id), true);
            $recipient->forceFill(['status' => MembershipStatus::Active, 'is_owner' => true, 'revision' => $recipient->revision + 1])->save();
            $source->forceFill(['is_owner' => false, 'revision' => $source->revision + 1])->save();
            $source = $source->refresh();
            DB::connection($source->getConnectionName())->afterCommit(fn () => $this->audits->record(
                'membership.ownership_transferred',
                subject: new SubjectReference($source->subject_type, $source->subject_id),
                actor: $actor,
                metadata: ['membership_id' => $source->identifier(), ...$this->authorization->metadata($authority)],
            ));

            return $source;
        }, 1);
    }
}
