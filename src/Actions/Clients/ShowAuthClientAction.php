<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/**
 * Returns one authorized first-party authentication client.
 */
final readonly class ShowAuthClientAction
{
    /**
     * Create the client detail use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
    ) {}

    /**
     * Authorize and return one route-resolved client.
     */
    public function execute(Authenticatable $actor, AuthClient $client): AuthClient
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.clients.view', $client);

        return $client;
    }
}
