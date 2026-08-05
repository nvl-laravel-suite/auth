<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;
use InvalidArgumentException;
use JsonException;

/**
 * Carries browser-safe WebAuthn options and encrypted-at-rest adapter state.
 */
final readonly class PasskeyCeremonyOptions
{
    /**
     * Create passkey ceremony options.
     *
     * @param  array<string, mixed>  $options
     * @param  array<string, mixed>  $state
     */
    public function __construct(
        public string $ceremonyId,
        public array $options,
        public array $state,
        public CarbonImmutable $expiresAt,
    ) {
        if (trim($this->ceremonyId) === ''
            || $this->ceremonyId !== trim($this->ceremonyId)
            || mb_strlen($this->ceremonyId) > 191
            || ! $this->expiresAt->isFuture()) {
            throw new InvalidArgumentException('Passkey ceremony identity and expiry are invalid.');
        }

        try {
            $options = json_encode($this->options, JSON_THROW_ON_ERROR);
            $state = json_encode($this->state, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Passkey ceremony data must be JSON-serializable.', previous: $exception);
        }

        if (strlen($options) > 131_072 || strlen($state) > 32_768) {
            throw new InvalidArgumentException('Passkey ceremony data exceeds its safe size limit.');
        }
    }
}
