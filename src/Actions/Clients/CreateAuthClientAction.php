<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\ValueObjects\AuthClientData;

/**
 * Creates one first-party authentication client.
 */
final readonly class CreateAuthClientAction
{
    /**
     * Create the client creation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Persist a new Auth client.
     */
    public function execute(Authenticatable $actor, AuthClientData $data): AuthClient
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.clients.create');
        $connection = (new AuthClient)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $data): AuthClient {
            $client = AuthClient::query()->create([
                'name' => $data->name,
                'surface' => $data->surface,
                'base_url' => rtrim($data->baseUrl, '/'),
                'return_paths' => $data->returnPaths,
                'allowed_origins' => $data->allowedOrigins,
                'allowed_flows' => $data->allowedFlows,
                'metadata' => $data->metadata,
                'is_active' => $data->active,
            ]);
            $this->audits->record(
                'client.created',
                actor: $actor,
                clientId: $client->identifier(),
                metadata: ['surface' => $client->surface],
            );

            return $client;
        }, 3);
    }
}
