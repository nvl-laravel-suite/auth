<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Nvl\Auth\Data\Mutations\ConsumeMagicLinkData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\FeatureGate;

/**
 * Orchestrates magic-link admission through the canonical challenge consumer.
 */
final readonly class ConsumeMagicLinkAction
{
    /**
     * Create the magic-link consumption use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ConsumeChallengeAction $challenges,
        private ConsumeChallengeByIdAction $directChallenges,
    ) {}

    /**
     * Consume a matching magic link.
     */
    public function execute(ConsumeMagicLinkData $data, string $purpose = 'login'): Challenge
    {
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Use);

        if ($data->challengeId !== null) {
            return $this->directChallenges->execute(
                AuthFeature::MagicLinks,
                AuthMessageType::MagicLink,
                $data->challengeId,
                $purpose,
                $data->token,
            );
        }

        return $this->challenges->execute(
            AuthFeature::MagicLinks,
            AuthMessageType::MagicLink,
            (string) $data->recipient,
            $purpose,
            $data->token,
        );
    }
}
