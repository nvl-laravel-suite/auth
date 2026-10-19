<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Contracts\ListOwnMembershipsContract;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use stdClass;

/**
 * Lists the authenticated global identity's own minimal active tenant projections.
 *
 * @api
 */
final readonly class ListOwnMembershipsAction implements ListOwnMembershipsContract
{
    public function __construct(private FeatureGate $features, private AuthOperationBoundary $operations,
        private AuthModelRegistry $models,
        private OwnershipReadiness $readiness,
    ) {}

    /** @return Collection<int, covariant array{tenant_id: string, membership_id: string, status: 'active'|'suspended'|'revoked', revision: int}|array{owner: array{version: int, type: string, storage: string, keyType: string, key: string}, membership_id: string, status: MembershipStatus, revision: int}> */
    public function execute(Authenticatable $subject): Collection
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Read);
        $this->operations->central(AuthIdentityOperation::MembershipDiscovery, $subject);
        $reference = SubjectReference::fromAuthenticatable($subject);

        if (config('nvl-auth.ownership.scoped') === true) {
            $this->readiness->assertActive('auth.memberships');
            $class = $this->models->ownerMembershipClass();
            $model = new $class;

            $projections = [];
            foreach ($model->getConnection()->table($model->getTable())->useWritePdo()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)
                ->where('status', 'active')->orderBy('owner_scope_key')->get() as $row) {
                $projections[] = $this->ownerProjection($row);
            }

            return new Collection($projections);
        }

        return TenantMembership::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)
            ->where('status', MembershipStatus::Active->value)->orderBy('tenant_id')->get()
            ->map(static fn (TenantMembership $membership): array => [
                'tenant_id' => $membership->tenant_id,
                'membership_id' => $membership->identifier(),
                'status' => $membership->status->value,
                'revision' => $membership->revision,
            ]);
    }

    /** @return array{owner: array{version: int, type: string, storage: string, keyType: string, key: string}, membership_id: string, status: MembershipStatus, revision: int} */
    private function ownerProjection(stdClass $row): array
    {
        if (! is_string($row->owner_reference) || ! is_string($row->id) || (! is_int($row->revision) && ! is_string($row->revision))) {
            throw new OwnershipViolation('Membership discovery requires canonical persisted scalar identities.');
        }
        $owner = OwnerReference::fromJson($row->owner_reference);
        if ($row->owner_scope_key !== $owner->scopeKey()) {
            throw new OwnershipViolation('The membership partition is invalid.');
        }

        return ['owner' => $owner->toArray(), 'membership_id' => $row->id, 'status' => MembershipStatus::Active, 'revision' => (int) $row->revision];
    }
}
