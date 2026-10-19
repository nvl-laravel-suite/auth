<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Membership;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\OwnerMembershipLock;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

/**
 * Owns the transactional native membership lifecycle and permanent last-owner lock.
 * This capability owns its source transaction so host and invitation workflows share one invariant.
 *
 * @api
 */
final readonly class OwnerMemberships
{
    public function __construct(
        private AuthModelRegistry $models,
        private OwnershipBoundary $boundary,
        private OwnershipContext $context,
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private MembershipPrincipalResolver $principals,
        private TenantMembershipAssignments $assignments,
        private AuthCommittedAudit $audits,
    ) {}

    /** Explicitly provision an existing principal; authentication never calls this method. */
    public function provision(SystemMutationContext $authority, SubjectReference $subject): OwnerMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);
        $this->context->requireOwner();
        $actor = $this->authorization->authorize($authority, 'nvl.auth.memberships.enroll');
        $class = $this->models->ownerMembershipClass();

        return (new $class)->getConnection()->transaction(function () use ($class, $subject, $authority, $actor): OwnerMembership {
            $this->lock(true);
            $this->principals->resolve($subject, true);
            $membership = $this->query()->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)->lockForUpdate()->first();
            if (! $membership instanceof OwnerMembership) {
                $membership = new $class;
                $membership->fill(['subject_type' => $subject->type, 'subject_id' => $subject->identifier]);
            }
            $membership->forceFill(['status' => MembershipStatus::Active, 'is_owner' => true, 'revision' => $membership->exists ? $membership->revision + 1 : 1])->save();

            $this->audits->record($membership->getConnection(), 'membership.owner_provisioned', subject: $subject, actor: $actor, metadata: $this->authorization->metadata($authority));

            return $membership->refresh();
        }, 3);
    }

    /** Enroll a principal only under explicit management authorization and an existing owner lock.
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function enroll(Authenticatable|SystemMutationContext $authority, SubjectReference $subject, array $roles = [], array $permissions = []): OwnerMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);
        $this->context->requireOwner();
        $actor = $this->authorization->authorize($authority, 'nvl.auth.memberships.enroll');
        $class = $this->models->ownerMembershipClass();

        return (new $class)->getConnection()->transaction(function () use ($class, $subject, $roles, $permissions, $authority, $actor): OwnerMembership {
            $this->lock();
            $principal = $this->principals->resolve($subject, true);
            $membership = $this->query()->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)->lockForUpdate()->first();
            if (! $membership instanceof OwnerMembership) {
                $membership = new $class;
                $membership->fill(['subject_type' => $subject->type, 'subject_id' => $subject->identifier]);
            }
            if (! $membership->exists || $membership->status === MembershipStatus::Revoked) {
                $membership->forceFill(['status' => MembershipStatus::Active, 'is_owner' => false, 'revision' => $membership->exists ? $membership->revision + 1 : 1])->save();
            }
            $this->assignments->sync($principal, $roles, $permissions);

            $this->audits->record($membership->getConnection(), 'membership.enrolled', subject: $subject, actor: $actor, metadata: $this->authorization->metadata($authority));

            return $membership->refresh();
        }, 3);
    }

    /** Apply one optimistic status transition without removing an owner's last active administrator. */
    public function setStatus(Authenticatable|SystemMutationContext $authority, Membership|string $membership, MembershipStatus $status, int $expectedRevision): OwnerMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Update);
        $candidate = $this->find($membership);
        $actor = $this->authorization->authorize($authority, 'nvl.auth.memberships.update', $candidate);

        return $candidate->getConnection()->transaction(function () use ($candidate, $status, $expectedRevision, $authority, $actor): OwnerMembership {
            $this->lock();
            $target = $this->find($candidate, true);
            if ($target->revision !== $expectedRevision) {
                throw new AuthException('membership_revision_conflict', 'The membership revision is stale.', 409);
            }
            if ($target->is_owner && $target->status === MembershipStatus::Active && $status !== MembershipStatus::Active
                && $this->query()->where('status', 'active')->where('is_owner', true)->orderBy('id')->limit(2)->lockForUpdate()->get(['id'])->get(1) === null) {
                throw new AuthException('membership_last_owner', 'The last active owner cannot be removed.', 409);
            }
            if ($status === MembershipStatus::Revoked) {
                $principal = $this->principals->resolve(new SubjectReference($target->subject_type, $target->subject_id), true);
                $this->assignments->sync($principal, [], []);
                $tokenClass = $this->models->personalAccessTokenClass();
                $this->boundary->query($tokenClass::query(), 'auth.tokens')->where('tokenable_type', $target->subject_type)->where('tokenable_id', $target->subject_id)->delete();
            }
            if ($target->status !== $status) {
                $target->forceFill(['status' => $status, 'revision' => $target->revision + 1])->save();
            }

            $this->audits->record($target->getConnection(), 'membership.'.$status->value, subject: new SubjectReference($target->subject_type, $target->subject_id), actor: $actor, metadata: $this->authorization->metadata($authority));

            return $target->refresh();
        }, 3);
    }

    /** Move administration between two memberships without transferring the resource owner. */
    public function transfer(Authenticatable|SystemMutationContext $authority, Membership|string $membership, string $recipientId, int $expectedRevision): OwnerMembership
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Update);
        $candidate = $this->find($membership);
        $actor = $this->authorization->authorize($authority, 'nvl.auth.memberships.transferOwnership', $candidate);

        return $candidate->getConnection()->transaction(function () use ($candidate, $recipientId, $expectedRevision, $authority, $actor): OwnerMembership {
            $this->lock();
            $source = $this->find($candidate, true);
            $recipient = $this->find($recipientId, true);
            if ($source->revision !== $expectedRevision) {
                throw new AuthException('membership_revision_conflict', 'The membership revision is stale.', 409);
            }
            if (! $source->is_owner || $source->status !== MembershipStatus::Active || $source->is($recipient)) {
                throw new AuthException('membership_ownership_invalid', 'Membership administration cannot be transferred.', 422);
            }
            $this->principals->resolve(new SubjectReference($recipient->subject_type, $recipient->subject_id), true);
            $recipient->forceFill(['status' => MembershipStatus::Active, 'is_owner' => true, 'revision' => $recipient->revision + 1])->save();
            $source->forceFill(['is_owner' => false, 'revision' => $source->revision + 1])->save();

            $this->audits->record($source->getConnection(), 'membership.ownership_transferred', subject: new SubjectReference($source->subject_type, $source->subject_id), actor: $actor, metadata: [...$this->authorization->metadata($authority), 'recipient_membership_id' => $recipient->id]);

            return $source->refresh();
        }, 3);
    }

    /** Protect all native last-owner responsibilities during a global principal mutation. */
    public function assertPrincipalCanBeDisabled(SubjectReference $subject): void
    {
        if (config('nvl-auth.features.memberships.enabled') !== true) {
            return;
        }
        $class = $this->models->ownerMembershipClass();
        $model = new $class;
        $connection = $model->getConnection();
        if ($connection->transactionLevel() < 1) {
            throw AuthException::invalidConfiguration('Global membership containment must share the principal source transaction.');
        }
        $ownerRows = $connection->table($model->getTable())->useWritePdo()->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)
            ->where('status', 'active')->where('is_owner', true)->orderBy('owner_scope_key')->get();
        foreach ($ownerRows as $row) {
            $lock = new OwnerMembershipLock;
            if ($lock->getConnection() !== $connection
                || $connection->table($lock->getTable())->where('owner_scope_key', $row->owner_scope_key)->lockForUpdate()->first() === null) {
                throw AuthException::invalidConfiguration('The native owner serialization row is unavailable.');
            }
            $active = $connection->table($model->getTable())->where('owner_scope_key', $row->owner_scope_key)->where('status', 'active')->where('is_owner', true)->orderBy('id')->limit(2)->lockForUpdate()->get(['id']);
            if ($active->count() < 2) {
                throw new AuthException('membership_last_owner', 'The principal retains last-owner responsibility.', 409);
            }
        }
    }

    /** Reload through the exact configured class and canonical owner predicate. */
    public function find(Membership|string $membership, bool $lock = false): OwnerMembership
    {
        $id = $membership instanceof Membership ? $membership->getKey() : $membership;

        return $this->query()->whereKey($id)->when($lock, static fn (Builder $query) => $query->lockForUpdate())->first()
            ?? throw new OwnershipViolation('The membership is unavailable in this owner.');
    }

    /** @return Builder<OwnerMembership> */
    private function query(): Builder
    {
        $class = $this->models->ownerMembershipClass();

        return $this->boundary->query($class::query(), 'auth.memberships');
    }

    /** Serialize every membership mutation on one retained, unique source row. */
    public function lock(bool $prepare = false): void
    {
        $owner = $this->context->requireOwner();
        $model = new OwnerMembershipLock;
        $membership = new ($this->models->ownerMembershipClass());
        if ($model->getConnection() !== $membership->getConnection() || $model->getConnection()->transactionLevel() < 1) {
            throw AuthException::invalidConfiguration('Membership serialization requires its owning source transaction.');
        }
        $attributes = $this->boundary->attributes('auth.membership_locks');
        if ($prepare) {
            $model->getConnection()->table($model->getTable())->insertOrIgnore([
                'id' => (string) Str::uuid(), ...$attributes, 'created_at' => now(), 'updated_at' => now(),
            ]);
        }
        $lock = $this->boundary->query(OwnerMembershipLock::query(), 'auth.membership_locks')->where('owner_scope_key', $owner->scopeKey())->lockForUpdate()->first();
        if (! $lock instanceof OwnerMembershipLock) {
            throw AuthException::invalidConfiguration('The owner membership lock has not been provisioned.');
        }
    }
}
