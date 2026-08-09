<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/**
 * Deletes one Auth client after host authorization.
 */
final readonly class DeleteAuthClientAction
{
    /**
     * Create the client deletion use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Delete a client and its correlation rows.
     */
    public function execute(Authenticatable $actor, AuthClient $client): void
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl-auth.clients.delete', $client);

        DB::connection($client->getConnectionName())->transaction(function () use ($actor, $client): void {
            $clientId = $client->identifier();
            $this->audits->record(
                'client.deleted',
                actor: $actor,
                clientId: $clientId,
                metadata: ['client_id' => $clientId],
            );
            AuthClient::query()->whereKey($clientId)->delete();
        }, 3);
    }
}
