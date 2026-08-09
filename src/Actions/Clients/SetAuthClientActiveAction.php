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
 * Activates or deactivates one first-party authentication client.
 */
final readonly class SetAuthClientActiveAction
{
    /**
     * Create the client-state use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Set the client state atomically and idempotently.
     */
    public function execute(
        Authenticatable $actor,
        AuthClient $client,
        bool $active,
    ): AuthClient {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.clients.update', $client);

        return DB::connection($client->getConnectionName())->transaction(function () use ($active, $actor, $client): AuthClient {
            /** @var AuthClient $locked */
            $locked = AuthClient::query()->lockForUpdate()->findOrFail($client->identifier());

            if ($locked->is_active !== $active) {
                $locked->forceFill(['is_active' => $active])->save();
                $this->audits->record(
                    $active ? 'client.activated' : 'client.deactivated',
                    actor: $actor,
                    clientId: $locked->identifier(),
                );
            }

            return $locked;
        }, 3);
    }
}
