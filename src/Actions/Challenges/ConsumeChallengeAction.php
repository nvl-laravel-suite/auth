<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Atomically verifies and consumes one package challenge.
 */
final readonly class ConsumeChallengeAction
{
    /**
     * Create the challenge consumption use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Consume a matching challenge or fail with a neutral error.
     */
    public function execute(
        AuthFeature $feature,
        AuthMessageType $messageType,
        string $recipient,
        string $purpose,
        string $secret,
    ): Challenge {
        $this->features->assertAllowed($feature, FeatureOperation::Use);
        $recipientHash = $this->hasher->hash('challenge-recipient', mb_strtolower(trim($recipient)));
        $secretHash = $this->hasher->hash(
            "challenge-{$messageType->value}-{$recipientHash}",
            $secret,
        );
        $connection = (new Challenge)->getConnectionName();

        $challenge = DB::connection($connection)->transaction(function () use (
            $messageType,
            $purpose,
            $recipientHash,
            $secretHash,
        ): ?Challenge {
            Challenge::query()
                ->where('type', $messageType->value)
                ->where('purpose', $purpose)
                ->where('recipient_hash', $recipientHash)
                ->whereNull('consumed_at')
                ->whereNull('revoked_at')
                ->where('expires_at', '<=', CarbonImmutable::now())
                ->update(['active_key' => null]);
            /** @var Challenge|null $challenge */
            $challenge = Challenge::query()
                ->where('type', $messageType->value)
                ->where('purpose', $purpose)
                ->where('recipient_hash', $recipientHash)
                ->where('secret_hash', $secretHash)
                ->lockForUpdate()
                ->first();

            if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
                /** @var Challenge|null $active */
                $active = Challenge::query()
                    ->where('type', $messageType->value)
                    ->where('purpose', $purpose)
                    ->where('recipient_hash', $recipientHash)
                    ->whereNull('consumed_at')
                    ->whereNull('revoked_at')
                    ->where('expires_at', '>', CarbonImmutable::now())
                    ->whereColumn('attempts', '<', 'max_attempts')
                    ->lockForUpdate()
                    ->first();

                if ($active instanceof Challenge) {
                    $attempts = min($active->attempts + 1, $active->max_attempts);
                    $active->forceFill([
                        'attempts' => $attempts,
                        'active_key' => $attempts >= $active->max_attempts ? null : $active->active_key,
                    ])->save();
                }

                return null;
            }

            $challenge->forceFill([
                'active_key' => null,
                'consumed_at' => CarbonImmutable::now(),
            ])->save();

            if (is_string($challenge->subject_type) && is_string($challenge->subject_id)) {
                $subject = new SubjectReference(
                    $challenge->subject_type,
                    $challenge->subject_id,
                );
            } else {
                $subject = null;
            }

            $this->audits->record(
                "{$messageType->value}.consumed",
                subject: $subject,
                metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $purpose],
            );

            return $challenge;
        }, 3);

        if (! $challenge instanceof Challenge) {
            $this->audits->record(
                "{$messageType->value}.failed",
                outcome: 'failure',
                metadata: ['purpose' => $purpose],
            );

            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }

        return $challenge;
    }
}
