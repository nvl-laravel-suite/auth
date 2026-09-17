<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Data\Mutations\EnrollMembershipData;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Services\TenantBoundary;

/** Owns transactional membership mutation mechanics shared by public Actions. */
final readonly class MembershipMutator
{
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private MembershipLocator $memberships,
        private MembershipWriter $writer,
        private MembershipOwnerGuard $owners,
        private TenantMembershipAssignments $assignments,
        private TenantContext $context,
        private TenantBoundary $boundary,
        private AuthAuditRecorder $audits,
    ) {}

    public function enroll(Authenticatable|SystemMutationContext $authority, EnrollMembershipData $data): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.enroll');

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($actor, $authority, $data): TenantMembership {
            $this->owners->lock($this->context->requireTenant());
            $principal = $this->principals->resolve($data->subject, true);
            $membership = $this->writer->enroll($data->subject);
            $this->assignments->sync($principal, $data->roles, $data->permissions);
            DB::connection((new TenantMembership)->getConnectionName())->afterCommit(fn () => $this->audits->record(
                'membership.enrolled', subject: $data->subject, actor: $actor,
                metadata: ['membership_id' => $membership->identifier(), ...$this->authorization->metadata($authority)],
            ));

            return $membership;
        }, 3);
    }

    public function setStatus(
        Authenticatable|SystemMutationContext $authority,
        TenantMembership|string $membership,
        MembershipStatus $status,
        int $expectedRevision,
    ): TenantMembership {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Update);

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($authority, $expectedRevision, $membership, $status): TenantMembership {
            $target = $this->memberships->find($membership, true);
            $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.update', $target);
            $this->owners->lock($this->context->requireTenant());
            $target = $this->memberships->find($target, true);
            $this->assertRevision($target, $expectedRevision);
            $this->principals->resolve(new SubjectReference($target->subject_type, $target->subject_id), true);
            if ($status !== MembershipStatus::Active) {
                $this->owners->assertCanRemoveOwner($target);
            }
            $updated = $this->writer->setStatus($target, $status);
            $this->scheduleAudit('membership.status_changed', $updated, $actor, $authority);

            return $updated;
        }, 3);
    }

    public function revoke(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, int $expectedRevision): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Revoke);

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($authority, $expectedRevision, $membership): TenantMembership {
            $target = $this->memberships->find($membership, true);
            $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.revoke', $target);
            $this->owners->lock($this->context->requireTenant());
            $target = $this->memberships->find($target, true);
            $this->assertRevision($target, $expectedRevision);
            $this->owners->assertCanRemoveOwner($target);
            $principal = $this->principals->resolve(new SubjectReference($target->subject_type, $target->subject_id), true);
            $this->assignments->sync($principal, [], []);
            $tenant = $this->context->requireTenant()->value;
            PersonalAccessToken::query()->where('tenant_id', $tenant)
                ->where('tokenable_type', $target->subject_type)->where('tokenable_id', $target->subject_id)->delete();
            $updated = $this->writer->setStatus($target, MembershipStatus::Revoked);
            $this->scheduleAudit('membership.revoked', $updated, $actor, $authority);

            return $updated;
        }, 3);
    }

    public function transfer(
        Authenticatable|SystemMutationContext $authority,
        TenantMembership|string $membership,
        TransferMembershipOwnershipData $data,
    ): TenantMembership {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Update);

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($authority, $data, $membership): TenantMembership {
            $source = $this->memberships->find($membership, true);
            $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.transferOwnership', $source);
            $this->owners->lock($this->context->requireTenant());
            $source = $this->memberships->find($source, true);
            $recipient = $this->memberships->find($data->recipientMembershipId, true);
            $this->assertRevision($source, $data->expectedRevision);
            if (! $source->is_owner || $source->status !== MembershipStatus::Active || $source->is($recipient)) {
                throw new AuthException('membership_ownership_invalid', 'Membership ownership cannot be transferred.', 422);
            }
            $this->principals->resolve(new SubjectReference($recipient->subject_type, $recipient->subject_id), true);
            $recipient->forceFill(['status' => MembershipStatus::Active, 'is_owner' => true, 'revision' => $recipient->revision + 1])->save();
            $source->forceFill(['is_owner' => false, 'revision' => $source->revision + 1])->save();
            $source = $source->refresh();
            $this->scheduleAudit('membership.ownership_transferred', $source, $actor, $authority);

            return $source;
        }, 3);
    }

    public function provisionOwner(SystemMutationContext $authority, SubjectReference $subject): TenantMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.memberships.enroll');

        return DB::connection((new TenantMembership)->getConnectionName())->transaction(function () use ($actor, $authority, $subject): TenantMembership {
            $tenant = $this->context->requireTenant();
            TenantMembershipLock::query()->firstOrCreate([
                ...$this->boundary->attributes('auth.membership_locks'),
                'tenant_id' => $tenant->value,
            ]);
            $this->owners->lock($tenant);
            $this->principals->resolve($subject, true);
            $membership = $this->writer->enroll($subject);
            if (! $membership->is_owner) {
                $membership->forceFill(['is_owner' => true, 'status' => MembershipStatus::Active, 'revision' => $membership->revision + 1])->save();
            }
            $membership = $membership->refresh();
            $this->scheduleAudit('membership.owner_provisioned', $membership, $actor, $authority);

            return $membership;
        }, 3);
    }

    private function assertRevision(TenantMembership $membership, int $expected): void
    {
        if ($membership->revision !== $expected) {
            throw new AuthException('membership_revision_conflict', 'The membership revision is stale.', 409);
        }
    }

    private function scheduleAudit(
        string $action,
        TenantMembership $membership,
        ?Authenticatable $actor,
        Authenticatable|SystemMutationContext $authority,
    ): void {
        DB::connection($membership->getConnectionName())->afterCommit(fn () => $this->audits->record(
            $action,
            subject: new SubjectReference($membership->subject_type, $membership->subject_id),
            actor: $actor,
            metadata: ['membership_id' => $membership->identifier(), ...$this->authorization->metadata($authority)],
        ));
    }
}
