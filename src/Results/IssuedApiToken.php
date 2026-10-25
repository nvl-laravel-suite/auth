<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Carbon\CarbonImmutable;

/**
 * Returns newly issued token metadata and its one-time Sanctum plaintext token.
 *
 * @api
 */
final readonly class IssuedApiToken
{
    /**
     * Create an issued token result.
     *
     * @param  array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}  $token
     */
    public function __construct(public array $token, public string $plainTextToken) {}

    /**
     * Redact the plaintext credential during inspection.
     *
     * @return array{token_id: string, plain_text_token: string}
     */
    public function __debugInfo(): array
    {
        return ['token_id' => $this->token['id'], 'plain_text_token' => '[REDACTED]'];
    }
}
