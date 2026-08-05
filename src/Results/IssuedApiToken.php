<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Returns newly issued token metadata and its one-time Sanctum plaintext token.
 */
final readonly class IssuedApiToken
{
    /**
     * Create an issued token result.
     */
    public function __construct(
        public ApiTokenSnapshot $token,
        public string $plainTextToken,
    ) {}

    /**
     * Redact the plaintext credential during inspection.
     *
     * @return array{token_id: string, plain_text_token: string}
     */
    public function __debugInfo(): array
    {
        return ['token_id' => $this->token->id, 'plain_text_token' => '[REDACTED]'];
    }
}
