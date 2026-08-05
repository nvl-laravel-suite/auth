<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;

/**
 * Exposes provider-neutral Sanctum token metadata without its secret.
 */
final readonly class ApiTokenSnapshot
{
    /**
     * Create a token snapshot.
     *
     * @param  list<string>  $abilities
     */
    public function __construct(
        public string $id,
        public string $name,
        public array $abilities,
        public ?CarbonImmutable $lastUsedAt,
        public ?CarbonImmutable $expiresAt,
        public CarbonImmutable $createdAt,
    ) {}
}
