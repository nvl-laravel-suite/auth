<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Marks one host-owned email as verified after transport signature validation.
 */
final readonly class VerifyEmailAction
{
    /**
     * Create the email verification use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Mark the subject's email as verified idempotently.
     */
    public function execute(Authenticatable&MustVerifyEmail $subject): bool
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Use);

        if ($subject->hasVerifiedEmail()) {
            return false;
        }

        if (! $subject->markEmailAsVerified()) {
            return false;
        }

        $reference = SubjectReference::fromAuthenticatable($subject);
        event(new Verified($subject));
        $this->audits->record('email.verified', subject: $reference, actor: $subject);

        return true;
    }
}
