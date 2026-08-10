<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\OpaqueTokenFactory;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Issues one hashed challenge and emits a transport-neutral delivery payload.
 */
final readonly class IssueChallengeAction
{
    /**
     * Create the challenge issuance use case.
     */
    public function __construct(
        private FeatureGate $features,
        private OpaqueTokenFactory $tokens,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Issue a token or numeric-code challenge.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, mixed>  $metadata
     */
    public function execute(
        AuthFeature $feature,
        AuthMessageType $messageType,
        string $recipient,
        string $purpose,
        CarbonImmutable $expiresAt,
        bool $numeric = false,
        int $digits = 6,
        int $maxAttempts = 5,
        ?SubjectReference $subject = null,
        array $payload = [],
        array $metadata = [],
        ?string $locale = null,
        bool $withFallbackCode = false,
        int $fallbackDigits = 6,
    ): IssuedChallenge {
        $this->features->assertAllowed($feature, FeatureOperation::Issue);

        if (trim($recipient) === '' || mb_strlen($recipient) > 320) {
            throw new InvalidArgumentException('Challenge recipients must contain between one and 320 characters.');
        }

        if (trim($purpose) === '' || mb_strlen($purpose) > 120) {
            throw new InvalidArgumentException('Challenge purposes must contain between one and 120 characters.');
        }

        if (! $expiresAt->isFuture()) {
            throw new InvalidArgumentException('Challenge expiry must be in the future.');
        }

        if ($maxAttempts < 1
            || $maxAttempts > 100
            || ($numeric && ($digits < 4 || $digits > 10))
            || ($withFallbackCode && ($numeric || $fallbackDigits < 4 || $fallbackDigits > 10))) {
            throw new InvalidArgumentException('Challenge attempt or numeric-code configuration is invalid.');
        }

        $normalizedRecipient = mb_strtolower(trim($recipient));
        $recipientHash = $this->hasher->hash('challenge-recipient', $normalizedRecipient);
        $secret = $numeric
            ? str_pad((string) random_int(0, (10 ** $digits) - 1), $digits, '0', STR_PAD_LEFT)
            : $this->tokens->make();
        $secretHash = $this->hasher->hash(
            "challenge-{$messageType->value}-{$recipientHash}",
            $secret,
        );
        $fallbackCode = $withFallbackCode
            ? str_pad((string) random_int(0, (10 ** $fallbackDigits) - 1), $fallbackDigits, '0', STR_PAD_LEFT)
            : null;
        $secondarySecretHash = $fallbackCode === null
            ? null
            : $this->hasher->hash("challenge-{$messageType->value}-secondary-{$recipientHash}", $fallbackCode);
        $activeKey = $this->hasher->hash(
            'active-challenge',
            $messageType->value."\0".$purpose."\0".$recipientHash,
        );
        $connection = (new Challenge)->getConnectionName();

        try {
            return DB::connection($connection)->transaction(function () use (
                $activeKey,
                $expiresAt,
                $feature,
                $locale,
                $maxAttempts,
                $messageType,
                $metadata,
                $normalizedRecipient,
                $payload,
                $purpose,
                $recipientHash,
                $secret,
                $secretHash,
                $subject,
                $fallbackCode,
                $secondarySecretHash,
            ): IssuedChallenge {
                Challenge::query()
                    ->where('active_key', $activeKey)
                    ->update(['active_key' => null, 'revoked_at' => CarbonImmutable::now()]);
                $challenge = Challenge::query()->create([
                    'type' => $messageType->value,
                    'purpose' => $purpose,
                    'subject_type' => $subject?->type,
                    'subject_id' => $subject?->identifier,
                    'recipient_hash' => $recipientHash,
                    'secret_hash' => $secretHash,
                    'secondary_secret_hash' => $secondarySecretHash,
                    'active_key' => $activeKey,
                    'payload' => $payload,
                    'max_attempts' => $maxAttempts,
                    'expires_at' => $expiresAt,
                ]);
                AuthDeliveryRequested::dispatch(new AuthDeliveryRequest(
                    messageId: (string) Str::uuid(),
                    feature: $feature,
                    type: $messageType,
                    recipient: $normalizedRecipient,
                    payload: [
                        ...$payload,
                        'challenge_id' => $challenge->identifier(),
                        'secret' => $secret,
                        'code' => $fallbackCode,
                        'purpose' => $purpose,
                    ],
                    expiresAt: $expiresAt,
                    locale: $locale,
                    metadata: ['challenge_id' => $challenge->identifier(), ...$metadata],
                ));
                $this->audits->record(
                    "{$feature->value}.issued",
                    subject: $subject,
                    metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $purpose],
                );

                return new IssuedChallenge($challenge, $secret, $fallbackCode);
            }, 3);
        } catch (QueryException $exception) {
            if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true)
                && (str_contains($exception->getMessage(), 'nvl_auth_challenges_active_key_unique')
                    || str_contains($exception->getMessage(), 'auth_challenges.active_key'))) {
                throw new AuthException(
                    'challenge_issue_conflict',
                    'An authentication challenge is already being issued.',
                    409,
                    previous: $exception,
                );
            }

            throw $exception;
        }
    }
}
