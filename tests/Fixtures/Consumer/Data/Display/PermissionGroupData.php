<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * Deterministic permission group option with its bounded catalog count.
 *
 * @api
 */
final class PermissionGroupData implements Arrayable, JsonSerializable
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

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'value' => $this->value,
            'label' => $this->label,
            'permissionsCount' => $this->permissionsCount,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /** @param array<string, mixed> $attributes */
    public static function from(array $attributes): self
    {
        return new self(
            value: $attributes['value'],
            label: $attributes['label'],
            permissionsCount: $attributes['permissionsCount'],
        );
    }
}
