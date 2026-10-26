<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;

/**
 * Complete native AuthEmailVerification operations.
 *
 * @api
 */
final readonly class AuthEmailVerification
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private AuthConfiguration $configuration, private AuthAuditRecorder $audits, private DomainEventDispatcher $domainEvents, private ConnectionCommitCallbacks $eventCommits) {}

    /**
     * Request verification for one host-owned subject.
     */
    public function request(Authenticatable&MustVerifyEmail $subject, ?string $locale = null): void
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Issue);
        if ($subject->hasVerifiedEmail()) {
            return;
        }
        $reference = SubjectReference::fromAuthenticatable($subject);
        $expiresAt = CarbonImmutable::now('UTC')->addMinutes($this->configuration->integerBetween('features.email_verification.settings.ttl_minutes', 60, 1, 10080));
        $this->domainEvents->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: AuthFeature::EmailVerification, type: AuthMessageType::EmailVerification, recipient: $subject->getEmailForVerification(), payload: ['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'email_hash' => sha1($subject->getEmailForVerification())], expiresAt: $expiresAt, locale: $locale), $this->deliveryContext->capture(true)), (new AuthAudit)->getConnection());
        $this->audits->record('email_verification.requested', subject: $reference, actor: $subject);
    }

    /**
     * Mark the subject's email as verified idempotently.
     */
    public function verify(Authenticatable&MustVerifyEmail $subject): bool
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Use);
        if ($subject->hasVerifiedEmail()) {
            return false;
        }
        $verify = function () use ($subject): bool {
            if (! $subject->markEmailAsVerified()) {
                return false;
            }
            $reference = SubjectReference::fromAuthenticatable($subject);
            $event = new Verified($subject);
            if ($subject instanceof Model) {
                $this->eventCommits->afterCommit($subject->getConnection(), static function () use ($event): void {
                    event($event);
                });
            } else {
                event($event);
            }
            $this->audits->record('email.verified', subject: $reference, actor: $subject);

            return true;
        };

        return $subject instanceof Model ? $subject->getConnection()->transaction($verify) : $verify();
    }
}
