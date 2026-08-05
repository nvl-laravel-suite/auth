<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Orchestrates security-code policy through the canonical challenge issuer.
 */
final readonly class RequestSecurityCodeAction
{
    /**
     * Create the security-code request use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private IssueChallengeAction $challenges,
    ) {}

    /**
     * Issue one security code.
     *
     * @param  array<string, mixed>  $payload
     */
    public function execute(
        RequestSecurityCodeData $data,
        ?SubjectReference $subject = null,
        array $payload = [],
        ?string $locale = null,
    ): IssuedChallenge {
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Issue);

        return $this->challenges->execute(
            feature: AuthFeature::SecurityCodes,
            messageType: AuthMessageType::SecurityCode,
            recipient: $data->recipient,
            purpose: $data->purpose,
            expiresAt: CarbonImmutable::now()->addMinutes(
                $this->configuration->integerBetween('features.security_codes.settings.ttl_minutes', 10, 1, 10_080),
            ),
            numeric: true,
            digits: $this->configuration->integerBetween('features.security_codes.settings.digits', 6, 4, 10),
            maxAttempts: $this->configuration->integerBetween('features.security_codes.settings.max_attempts', 5, 1, 100),
            subject: $subject,
            payload: $payload,
            locale: $locale,
        );
    }
}
