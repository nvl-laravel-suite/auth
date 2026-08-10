<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\Models\Challenge;

/**
 * Returns a persisted challenge and its one-time plaintext secret.
 */
final readonly class IssuedChallenge
{
    /**
     * Create a challenge issuance result.
     */
    public function __construct(
        public Challenge $challenge,
        public string $secret,
        public ?string $fallbackCode = null,
    ) {}

    /**
     * Redact the secret during inspection.
     *
     * @return array{challenge_id: string, secret: string, fallback_code: string|null}
     */
    public function __debugInfo(): array
    {
        return [
            'challenge_id' => $this->challenge->identifier(),
            'secret' => '[REDACTED]',
            'fallback_code' => $this->fallbackCode === null ? null : '[REDACTED]',
        ];
    }
}
