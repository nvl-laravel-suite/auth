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
 * Revokes every provider-owned token for one subject.
 */
final readonly class RevokeAllApiTokensAction
{
    /**
     * Create the bulk token revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ApiTokenManager $tokens,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke all tokens and return the affected count.
     */
    public function execute(Authenticatable $subject): int
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Revoke);
        $count = $this->tokens->revokeAll($subject);
        $this->audits->record(
            'api_token.revoked_all',
            subject: SubjectReference::fromAuthenticatable($subject),
            actor: $subject,
            metadata: ['count' => $count],
        );

        return $count;
    }
}
