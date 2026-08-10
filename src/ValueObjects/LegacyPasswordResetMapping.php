<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

/** Validated legacy password-reset token source mapping. */
final readonly class LegacyPasswordResetMapping
{
    /** @param array{email: string, token: string, created_at: string|null} $columns */
    public function __construct(
        public string $table,
        public int $expectedCount,
        public array $columns,
    ) {}
}
