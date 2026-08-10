<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;

/**
 * Carries a transport-neutral message request to host delivery listeners.
 */
final readonly class AuthDeliveryRequest
{
    /**
     * Create a delivery request.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $messageId,
        public AuthFeature $feature,
        public AuthMessageType $type,
        public string $recipient,
        public array $payload,
        public CarbonImmutable $expiresAt,
        public ?string $locale = null,
        public array $metadata = [],
    ) {
        $supportedType = match ($this->feature) {
            AuthFeature::Invitations => AuthMessageType::Invitation,
            AuthFeature::MagicLinks => AuthMessageType::MagicLink,
            AuthFeature::SecurityCodes => AuthMessageType::SecurityCode,
            AuthFeature::Password => AuthMessageType::PasswordReset,
            AuthFeature::EmailVerification => AuthMessageType::EmailVerification,
            default => null,
        };

        if ($supportedType !== $this->type) {
            throw new InvalidArgumentException('Auth delivery feature and message type are incompatible.');
        }

        if (trim($this->messageId) === ''
            || $this->messageId !== trim($this->messageId)
            || mb_strlen($this->messageId) > 191
            || preg_match('/[\x00-\x1F\x7F]/', $this->messageId) === 1
            || trim($this->recipient) === ''
            || $this->recipient !== trim($this->recipient)
            || mb_strlen($this->recipient) > 320
            || preg_match('/[\x00-\x1F\x7F]/', $this->recipient) === 1) {
            throw new InvalidArgumentException('Auth delivery message and recipient identifiers are required.');
        }

        if (! $this->expiresAt->isFuture()) {
            throw new InvalidArgumentException('Auth delivery expiry must be in the future.');
        }

        if ($this->locale !== null
            && (preg_match('/\A[a-zA-Z]{2,3}(?:[-_][a-zA-Z0-9]{2,8})*\z/', $this->locale) !== 1
                || mb_strlen($this->locale) > 35)) {
            throw new InvalidArgumentException('Auth delivery locale is invalid.');
        }

        try {
            $payload = json_encode($this->payload, JSON_THROW_ON_ERROR);
            $metadata = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Auth delivery payloads must be JSON-serializable.', previous: $exception);
        }

        if (strlen($payload) > 32_768 || strlen($metadata) > 16_384) {
            throw new InvalidArgumentException('Auth delivery payloads exceed their safe size limit.');
        }
    }

    /**
     * Redact secret-bearing delivery data during inspection.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'message_id' => $this->messageId,
            'feature' => $this->feature->value,
            'type' => $this->type->value,
            'recipient' => '[REDACTED]',
            'payload_keys' => array_keys($this->payload),
            'expires_at' => $this->expiresAt->toIso8601String(),
            'locale' => $this->locale,
            'metadata_keys' => array_keys($this->metadata),
        ];
    }
}
