<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

/** Validated legacy principal source mapping. */
final readonly class LegacyPrincipalMapping
{
    /**
     * @param  array<string, string|null>  $columns
     * @param  array<string, string>  $extensionColumns
     */
    public function __construct(
        public string $table,
        public int $expectedCount,
        public array $columns,
        public array $extensionColumns,
    ) {}
}
