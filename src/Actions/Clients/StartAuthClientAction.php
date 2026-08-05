<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\AuthClientStartResult;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthPipelineContext;

/**
 * Validates one hosted-client authentication start request.
 */
final readonly class StartAuthClientAction
{
    /**
     * Create the hosted-client start use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Resolve an allowlisted return target for an active client.
     */
    public function execute(
        string $clientId,
        string $flow,
        string $returnPath,
        ?string $origin = null,
    ): AuthClientStartResult {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);

        return $this->pipeline->run(
            'client_started',
            new AuthPipelineContext('client_started', ['client_id' => $clientId, 'flow' => $flow]),
            function () use ($clientId, $flow, $origin, $returnPath): AuthClientStartResult {
                /** @var AuthClient|null $client */
                $client = AuthClient::query()->whereKey($clientId)->where('is_active', true)->first();

                if (! $client instanceof AuthClient) {
                    throw new AuthException('client_unavailable', 'The authentication client is unavailable.', 404);
                }

                $flows = is_array($client->allowed_flows) ? $client->allowed_flows : [];
                $paths = is_array($client->return_paths) ? $client->return_paths : [];
                $origins = is_array($client->allowed_origins) ? $client->allowed_origins : [];

                if (! in_array($flow, $flows, true) || ! in_array($returnPath, $paths, true)) {
                    throw new AuthException('client_redirect_invalid', 'The client flow or return target is not allowlisted.', 422);
                }

                if (($origins !== [] && $origin === null)
                    || ($origin !== null && ! in_array($origin, $origins, true))) {
                    throw new AuthException('client_origin_invalid', 'The client origin is not allowlisted.', 422);
                }

                DB::connection($client->getConnectionName())->transaction(function () use ($client, $flow): void {
                    AuthClient::query()->whereKey($client->identifier())->update(['last_used_at' => CarbonImmutable::now()]);
                    $this->audits->record(
                        'client.started',
                        clientId: $client->identifier(),
                        metadata: ['flow' => $flow],
                    );
                }, 3);

                return new AuthClientStartResult($client, $flow, rtrim($client->base_url, '/').$returnPath);
            },
        );
    }
}
