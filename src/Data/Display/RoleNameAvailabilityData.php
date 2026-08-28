<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Consumer-safe result for a role canonical-name availability check.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class RoleNameAvailabilityData extends Data
{
    use DataTransform;

    /**
     * Create a role name availability result.
     */
    public function __construct(
        public readonly string $name,
        public readonly bool $available,
        public readonly ?string $conflictingRoleId,
    ) {}
}
