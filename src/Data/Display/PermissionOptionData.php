<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Auth\Models\Permission;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Minimal permission identity for bounded consumer selectors and resolution results.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class PermissionOptionData extends Data
{
    use DataTransform;

    public readonly string $label;

    public readonly string $group;

    /**
     * Create a permission option projection.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        string $label,
        public readonly ?string $description,
        string $group,
    ) {
        $label = trim($label);
        $this->label = $label !== '' ? $label : $name;
        $this->group = self::normalizeGroup($group);
    }

    /**
     * Build a permission option from an already selected package model row.
     */
    public static function fromModel(Permission $permission): self
    {
        return new self(
            id: $permission->id,
            name: $permission->name,
            label: $permission->display_name ?? '',
            description: $permission->description,
            group: $permission->group ?? '',
        );
    }

    /**
     * Normalize the uncategorized permission group.
     */
    public static function normalizeGroup(?string $group): string
    {
        $group = trim((string) $group);

        return $group !== '' ? $group : 'general';
    }
}
