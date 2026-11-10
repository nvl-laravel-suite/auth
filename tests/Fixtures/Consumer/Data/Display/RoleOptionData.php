<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Nvl\Auth\Models\Role;

/**
 * Minimal role identity for bounded consumer selectors and resolution results.
 *
 * @api
 */
final class RoleOptionData implements Arrayable, JsonSerializable
{
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
     *
     * @internal
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

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'label' => $this->label,
            'description' => $this->description,
            'isSystem' => $this->isSystem,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
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
