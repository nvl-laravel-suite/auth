<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\VerifyEmailContract;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;

/**
 * Marks one host-owned email as verified after transport signature validation.
 *
 * @api
 */
final readonly class VerifyEmailAction implements VerifyEmailContract
{
    /**
     * Create the email verification use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
        private ConnectionCommitCallbacks $eventCommits,
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
