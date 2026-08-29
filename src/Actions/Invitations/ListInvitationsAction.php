<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\SecretHasher;

/**
 * Lists invitation records after host business authorization.
 */
final readonly class ListInvitationsAction
{
    /**
     * Create the invitation listing use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private SecretHasher $hasher,
    ) {}

    /**
     * Return a bounded invitation page.
     *
     * @return LengthAwarePaginator<int, Invitation>
     */
    public function execute(
        Authenticatable $actor,
        ?InvitationIndexQueryData $filters = null,
        int $perPage = 25,
    ): LengthAwarePaginator {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.invitations.viewAny');

        $filters ??= new InvitationIndexQueryData;
        $query = Invitation::query()
            ->when($filters->recipient !== null, fn ($query) => $query->where(
                'recipient_hash',
                $this->hasher->hash('invitation-recipient', mb_strtolower(trim((string) $filters->recipient))),
            ))
            ->when($filters->type !== null, fn ($query) => $query->where('type', $filters->type))
            ->when($filters->types !== null, fn ($query) => $query->whereIn('type', $filters->types))
            ->when($filters->purpose !== null, fn ($query) => $query->where('purpose', $filters->purpose))
            ->when($filters->expiresAfter !== null, fn ($query) => $query->where('expires_at', '>=', $filters->expiresAfter))
            ->when($filters->expiresBefore !== null, fn ($query) => $query->where('expires_at', '<=', $filters->expiresBefore))
            ->when($filters->context !== null, fn ($query) => $query->where(
                'context_hash',
                $this->hasher->hash('invitation-context', trim((string) $filters->context)),
            ));

        match ($filters->lifecycle) {
            'active' => $query->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '>', now()),
            'accepted' => $query->whereNotNull('accepted_at'),
            'revoked' => $query->whereNotNull('revoked_at'),
            'expired' => $query->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '<=', now()),
            default => null,
        };

        return $query->latest()->paginate($filters->perPage ?? max(1, min($perPage, 100)));
    }
}
