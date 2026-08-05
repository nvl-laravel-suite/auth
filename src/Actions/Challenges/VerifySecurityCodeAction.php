<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Nvl\Auth\Data\Mutations\VerifySecurityCodeData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\FeatureGate;

/**
 * Orchestrates security-code verification through the canonical challenge consumer.
 */
final readonly class VerifySecurityCodeAction
{
    /**
     * Create the security-code verification use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ConsumeChallengeAction $challenges,
    ) {}

    /**
     * Consume a matching security code.
     */
    public function execute(VerifySecurityCodeData $data): Challenge
    {
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Use);

        return $this->challenges->execute(
            AuthFeature::SecurityCodes,
            AuthMessageType::SecurityCode,
            $data->recipient,
            $data->purpose,
            $data->code,
        );
    }
}
