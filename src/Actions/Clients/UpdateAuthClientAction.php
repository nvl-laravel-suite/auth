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
 * Updates one first-party authentication client.
 */
final readonly class UpdateAuthClientAction
{
    /**
     * Create the client update use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Update a client atomically.
     */
    public function execute(
        Authenticatable $actor,
        AuthClient $client,
        AuthClientData $data,
    ): AuthClient {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.clients.update', $client);

        return DB::connection($client->getConnectionName())->transaction(function () use ($actor, $client, $data): AuthClient {
            /** @var AuthClient $locked */
            $locked = AuthClient::query()->lockForUpdate()->findOrFail($client->identifier());
            $locked->fill([
                'name' => $data->name,
                'surface' => $data->surface,
                'base_url' => rtrim($data->baseUrl, '/'),
                'return_paths' => $data->returnPaths,
                'allowed_origins' => $data->allowedOrigins,
                'allowed_flows' => $data->allowedFlows,
                'metadata' => $data->metadata,
                'is_active' => $data->active,
            ])->save();
            $this->audits->record('client.updated', actor: $actor, clientId: $locked->identifier());

            return $locked;
        }, 3);
    }
}
