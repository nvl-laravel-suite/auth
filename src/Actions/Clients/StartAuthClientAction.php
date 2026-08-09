<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Mutations\StartClientAuthData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\AuthClientStartResult;
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
    public function execute(StartClientAuthData $data): AuthClientStartResult
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);

        return $this->pipeline->run(
            'client_started',
            new AuthPipelineContext('client_started', ['client_id' => $data->clientId, 'flow' => $data->flow]),
            function () use ($data): AuthClientStartResult {
                /** @var AuthClient|null $client */
                $client = AuthClient::query()->whereKey($data->clientId)->where('is_active', true)->first();

                if (! $client instanceof AuthClient) {
                    throw new AuthException('client_unavailable', 'The authentication client is unavailable.', 404);
                }

                $flows = is_array($client->allowed_flows) ? $client->allowed_flows : [];
                $paths = is_array($client->return_paths) ? $client->return_paths : [];
                $origins = is_array($client->allowed_origins) ? $client->allowed_origins : [];

                if (! in_array($data->flow, $flows, true) || ! in_array($data->returnPath, $paths, true)) {
                    throw new AuthException('client_redirect_invalid', 'The client flow or return target is not allowlisted.', 422);
                }

                if (($origins !== [] && $data->origin === null)
                    || ($data->origin !== null && ! in_array($data->origin, $origins, true))) {
                    throw new AuthException('client_origin_invalid', 'The client origin is not allowlisted.', 422);
                }

                DB::connection($client->getConnectionName())->transaction(function () use ($client, $data): void {
                    AuthClient::query()->whereKey($client->identifier())->update(['last_used_at' => CarbonImmutable::now()]);
                    $this->audits->record(
                        'client.started',
                        clientId: $client->identifier(),
                        metadata: ['flow' => $data->flow],
                    );
                }, 3);

                return new AuthClientStartResult($client, $data->flow, rtrim($client->base_url, '/').$data->returnPath);
            },
        );
    }
}
