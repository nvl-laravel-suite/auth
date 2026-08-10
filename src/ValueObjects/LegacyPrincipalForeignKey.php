<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

/** One declared host foreign key to rewire onto the adopted principal table. */
final readonly class LegacyPrincipalForeignKey
{
    public function __construct(
        public string $table,
        public string $column,
        public string $name,
        public string $onDelete,
    ) {}
}
