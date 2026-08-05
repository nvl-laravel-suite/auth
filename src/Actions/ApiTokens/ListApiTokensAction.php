<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\ApiTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Lists provider-owned tokens for one host subject.
 */
final readonly class ListApiTokensAction
{
    /**
     * Create the token listing use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ApiTokenManager $tokens,
    ) {}

    /**
     * Return subject-owned tokens.
     *
     * @return list<ApiTokenSnapshot>
     */
    public function execute(Authenticatable $subject): array
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Read);

        return $this->tokens->list($subject);
    }
}
