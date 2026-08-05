<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Orchestrates magic-link policy through the canonical challenge issuer.
 */
final readonly class RequestMagicLinkAction
{
    /**
     * Create the magic-link request use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private IssueChallengeAction $challenges,
    ) {}

    /**
     * Issue one magic link.
     *
     * @param  array<string, mixed>  $payload
     */
    public function execute(
        string $recipient,
        string $purpose = 'login',
        ?SubjectReference $subject = null,
        array $payload = [],
        ?string $locale = null,
    ): IssuedChallenge {
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Issue);

        return $this->challenges->execute(
            feature: AuthFeature::MagicLinks,
            messageType: AuthMessageType::MagicLink,
            recipient: $recipient,
            purpose: $purpose,
            expiresAt: CarbonImmutable::now()->addMinutes(
                $this->configuration->integerBetween('features.magic_links.settings.ttl_minutes', 15, 1, 10_080),
            ),
            maxAttempts: $this->configuration->integerBetween('features.magic_links.settings.max_attempts', 5, 1, 100),
            subject: $subject,
            payload: $payload,
            locale: $locale,
        );
    }
}
