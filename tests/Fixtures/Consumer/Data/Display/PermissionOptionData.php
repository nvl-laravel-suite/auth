<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Nvl\Auth\Models\Permission;

/**
 * Minimal permission identity for bounded consumer selectors and resolution results.
 *
 * @api
 */
final class PermissionOptionData implements Arrayable, JsonSerializable
{
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
     *
     * @internal
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
        return self::normalizeNullableGroup($group) ?? 'general';
    }

    /**
     * Normalize a nullable group at package input and persistence boundaries.
     */
    public static function normalizeNullableGroup(?string $group): ?string
    {
        $group = trim(
            str_replace(["\t", "\n", "\v", "\r"], '', (string) $group),
            ' ',
        );

        return $group !== '' ? $group : null;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'label' => $this->label,
            'description' => $this->description,
            'group' => $this->group,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
