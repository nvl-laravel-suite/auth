<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

/** One pre-migration legacy table rename. */
final readonly class LegacyPrincipalTableStage
{
    public function __construct(
        public string $sourceTable,
        public string $stagingTable,
    ) {}
}
