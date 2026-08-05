<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/**
 * Lists first-party authentication clients.
 */
final readonly class ListAuthClientsAction
{
    /**
     * Create the client listing use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
    ) {}

    /**
     * Return a bounded client page.
     *
     * @return LengthAwarePaginator<int, AuthClient>
     */
    public function execute(Authenticatable $actor, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.clients.viewAny');

        return AuthClient::query()->latest()->paginate(max(1, min($perPage, 100)));
    }
}
