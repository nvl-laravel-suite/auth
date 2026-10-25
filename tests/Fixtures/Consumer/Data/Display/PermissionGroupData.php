<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Deterministic permission group option with its bounded catalog count.
 *
 * @api
 */
#[MapOutputName(CamelCaseMapper::class)]
final class PermissionGroupData extends Data
{
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
