<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

/** Complete bounded plan for one principal cutover. */
final readonly class PrincipalAdoptionPlan
{
    /**
     * @param  list<LegacyPrincipalTableStage>  $stages
     * @param  list<LegacyPrincipalForeignKey>  $foreignKeys
     */
    public function __construct(
        public ?string $connection,
        public array $stages,
        public LegacyPrincipalMapping $principals,
        public ?LegacyPasswordResetMapping $passwordResetTokens,
        public array $foreignKeys,
        public bool $dropSources,
    ) {}
}
