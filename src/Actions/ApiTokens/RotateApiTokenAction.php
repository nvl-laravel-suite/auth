<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\ApiTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\Services\ApiTokenPolicy;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Rotates one provider-owned personal access token.
 */
final readonly class RotateApiTokenAction
{
    /**
     * Create the token rotation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ApiTokenPolicy $policy,
        private ApiTokenManager $tokens,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Rotate one token and return its replacement secret once.
     */
    public function execute(
        Authenticatable $subject,
        string $tokenId,
        ApiTokenData $data,
    ): IssuedApiToken {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Update);
        $this->policy->authorize($subject, $data);
        $issued = $this->tokens->rotate($subject, $tokenId, $data);
        $this->audits->record(
            'api_token.rotated',
            subject: SubjectReference::fromAuthenticatable($subject),
            actor: $subject,
            metadata: ['old_token_id' => $tokenId, 'token_id' => $issued->token->id],
        );

        return $issued;
    }
}
