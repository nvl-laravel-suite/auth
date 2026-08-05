<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\ApiTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Revokes one provider-owned token as a containment operation.
 */
final readonly class RevokeApiTokenAction
{
    /**
     * Create the token revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ApiTokenManager $tokens,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke one token idempotently.
     */
    public function execute(Authenticatable $subject, string $tokenId): bool
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Revoke);
        $revoked = $this->tokens->revoke($subject, $tokenId);

        if ($revoked) {
            $this->audits->record(
                'api_token.revoked',
                subject: SubjectReference::fromAuthenticatable($subject),
                actor: $subject,
                metadata: ['token_id' => $tokenId],
            );
        }

        return $revoked;
    }
}
