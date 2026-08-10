<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Consumes either credential of a compound challenge through its callback-safe identifier.
 */
final readonly class ConsumeChallengeByIdAction
{
    /** Create the direct challenge consumption use case. */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /** Consume a primary token or secondary code without scanning active challenge rows. */
    public function execute(
        AuthFeature $feature,
        AuthMessageType $messageType,
        string $challengeId,
        string $purpose,
        string $secret,
    ): Challenge {
        $this->features->assertAllowed($feature, FeatureOperation::Use);
        $connection = (new Challenge)->getConnectionName();

        $challenge = DB::connection($connection)->transaction(function () use (
            $challengeId,
            $messageType,
            $purpose,
            $secret,
        ): ?Challenge {
            /** @var Challenge|null $challenge */
            $challenge = Challenge::query()
                ->whereKey($challengeId)
                ->where('type', $messageType->value)
                ->where('purpose', $purpose)
                ->lockForUpdate()
                ->first();

            if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
                return null;
            }

            $primary = $this->hasher->hash(
                "challenge-{$messageType->value}-{$challenge->recipient_hash}",
                $secret,
            );
            $secondary = $this->hasher->hash(
                "challenge-{$messageType->value}-secondary-{$challenge->recipient_hash}",
                $secret,
            );

            if (! hash_equals($challenge->secret_hash, $primary)
                && (! is_string($challenge->secondary_secret_hash)
                    || ! hash_equals($challenge->secondary_secret_hash, $secondary))) {
                $attempts = min($challenge->attempts + 1, $challenge->max_attempts);
                $challenge->forceFill([
                    'attempts' => $attempts,
                    'active_key' => $attempts >= $challenge->max_attempts ? null : $challenge->active_key,
                ])->save();

                return null;
            }

            $challenge->forceFill([
                'active_key' => null,
                'consumed_at' => CarbonImmutable::now(),
            ])->save();

            return $challenge;
        }, 3);

        if (! $challenge instanceof Challenge) {
            $this->audits->record(
                "{$messageType->value}.failed",
                outcome: 'failure',
                metadata: ['challenge_id' => $challengeId, 'purpose' => $purpose],
            );

            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }

        $subject = is_string($challenge->subject_type) && is_string($challenge->subject_id)
            ? new SubjectReference($challenge->subject_type, $challenge->subject_id)
            : null;
        $this->audits->record(
            "{$messageType->value}.consumed",
            subject: $subject,
            metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $purpose],
        );

        return $challenge;
    }
}
