<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

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
    ) {}

    /**
     * Return a bounded invitation page.
     *
     * @return LengthAwarePaginator<int, Invitation>
     */
    public function execute(Authenticatable $actor, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.invitations.viewAny');

        return Invitation::query()->latest()->paginate(max(1, min($perPage, 100)));
    }
}
