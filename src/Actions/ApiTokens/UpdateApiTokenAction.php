<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\ApiTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\ApiTokenPolicy;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Updates provider-owned token metadata.
 */
final readonly class UpdateApiTokenAction
{
    /**
     * Create the token update use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ApiTokenPolicy $policy,
        private ApiTokenManager $tokens,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Update one subject-owned token.
     */
    public function execute(
        Authenticatable $subject,
        string $tokenId,
        ApiTokenData $data,
    ): ApiTokenSnapshot {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Update);
        $this->policy->authorize($subject, $data);
        $updated = $this->tokens->update($subject, $tokenId, $data);
        $this->audits->record(
            'api_token.updated',
            subject: SubjectReference::fromAuthenticatable($subject),
            actor: $subject,
            metadata: ['token_id' => $updated->id],
        );

        return $updated;
    }
}
