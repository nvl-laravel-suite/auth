<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Emits email-verification delivery data without sending a notification.
 */
final readonly class RequestEmailVerificationAction
{
    /**
     * Create the verification request use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Request verification for one host-owned subject.
     */
    public function execute(
        Authenticatable&MustVerifyEmail $subject,
        ?string $locale = null,
    ): void {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Issue);

        if ($subject->hasVerifiedEmail()) {
            return;
        }

        $reference = SubjectReference::fromAuthenticatable($subject);
        $expiresAt = CarbonImmutable::now()->addMinutes(
            $this->configuration->integerBetween(
                'features.email_verification.settings.ttl_minutes',
                60,
                1,
                10_080,
            ),
        );
        AuthDeliveryRequested::dispatch(new AuthDeliveryRequest(
            messageId: (string) Str::uuid(),
            feature: AuthFeature::EmailVerification,
            type: AuthMessageType::EmailVerification,
            recipient: $subject->getEmailForVerification(),
            payload: [
                'subject_type' => $reference->type,
                'subject_id' => $reference->identifier,
                'email_hash' => sha1($subject->getEmailForVerification()),
            ],
            expiresAt: $expiresAt,
            locale: $locale,
        ));
        $this->audits->record('email_verification.requested', subject: $reference, actor: $subject);
    }
}
