<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Deterministic permission group option with its bounded catalog count.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class PermissionGroupData extends Data
{
    use DataTransform;

    public readonly string $value;

    public readonly string $label;

    /**
     * Create a permission group projection.
     */
    public function __construct(
        string $value,
        string $label,
        public readonly int $permissionsCount,
    ) {
        $this->value = PermissionOptionData::normalizeGroup($value);
        $label = trim($label);
        $this->label = $label !== '' ? $label : $this->value;
    }
}
