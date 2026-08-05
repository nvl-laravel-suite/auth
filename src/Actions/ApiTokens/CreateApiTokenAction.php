<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\ApiTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\Services\ApiTokenPolicy;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Issues one provider-owned personal access token.
 */
final readonly class CreateApiTokenAction
{
    /**
     * Create the API-token issuance use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ApiTokenPolicy $policy,
        private ApiTokenManager $tokens,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Issue one token directly through the configured provider.
     */
    public function execute(Authenticatable $subject, ApiTokenData $data): IssuedApiToken
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Issue);
        $this->policy->authorize($subject, $data);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return $this->pipeline->run(
            'api_token_issued',
            new AuthPipelineContext('api_token_issued', ['abilities' => $data->abilities], $reference),
            function () use ($data, $reference, $subject): IssuedApiToken {
                $issued = $this->tokens->create($subject, $data);
                $this->audits->record(
                    'api_token.issued',
                    subject: $reference,
                    actor: $subject,
                    metadata: ['token_id' => $issued->token->id, 'abilities' => $data->abilities],
                );

                return $issued;
            },
        );
    }
}
