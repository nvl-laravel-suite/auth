<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Auth\Models\Role;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Minimal role identity for bounded consumer selectors and resolution results.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class RoleOptionData extends Data
{
    use DataTransform;

    public readonly string $label;

    /**
     * Create a role option projection.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        string $label,
        public readonly ?string $description,
        public readonly bool $isSystem,
    ) {
        $this->label = self::label($label, $name);
    }

    /**
     * Build a role option from an already selected package model row.
     */
    public static function fromModel(Role $role): self
    {
        return new self(
            id: $role->id,
            name: $role->name,
            label: $role->display_name ?? '',
            description: $role->description,
            isSystem: $role->is_system,
        );
    }

    /**
     * Normalize an optional display label without losing the canonical name.
     */
    private static function label(string $label, string $name): string
    {
        $label = trim($label);

        return $label !== '' ? $label : $name;
    }
}
