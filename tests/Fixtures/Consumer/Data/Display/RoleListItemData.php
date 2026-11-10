<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Collection;
use JsonSerializable;
use LogicException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

/**
 * Bounded role catalog row containing only allowlisted assignment identifiers.
 *
 * @api
 */
final class RoleListItemData implements Arrayable, JsonSerializable
{
    public readonly string $label;

    /**
     * Create a role catalog projection.
     *
     * @param  list<string>  $permissionIds
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        string $label,
        public readonly ?string $description,
        public readonly string $guard,
        public readonly bool $isSystem,
        public readonly int $priority,
        public readonly ?string $parentId,
        public readonly ?string $parentName,
        public readonly array $permissionIds,
        public readonly int $permissionsCount,
        public readonly int $usersCount,
        public readonly CarbonImmutable $createdAt,
    ) {
        $label = trim($label);
        $this->label = $label !== '' ? $label : $name;
    }

    /**
     * Build a catalog row without triggering relationship queries.
     *
     * @internal
     */
    public static function fromModel(Role $role): self
    {
        $parent = $role->relationLoaded('parent') ? $role->getRelation('parent') : null;
        $permissions = $role->relationLoaded('permissions')
            ? $role->getRelation('permissions')
            : null;
        $permissionIds = self::permissionIds($permissions);

        return new self(
            id: $role->id,
            name: $role->name,
            label: $role->display_name ?? '',
            description: $role->description,
            guard: $role->guard_name,
            isSystem: $role->is_system,
            priority: $role->priority,
            parentId: $role->parent_id,
            parentName: $parent instanceof Role ? $parent->name : null,
            permissionIds: $permissionIds,
            permissionsCount: self::count($role->getAttribute('permissions_count'), $permissionIds),
            usersCount: self::count($role->getAttribute('users_count')),
            createdAt: self::createdAt($role->getAttribute('created_at')),
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
            'guard' => $this->guard,
            'isSystem' => $this->isSystem,
            'priority' => $this->priority,
            'parentId' => $this->parentId,
            'parentName' => $this->parentName,
            'permissionIds' => $this->permissionIds,
            'permissionsCount' => $this->permissionsCount,
            'usersCount' => $this->usersCount,
            'createdAt' => $this->createdAt->format(DATE_ATOM),
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Extract loaded permission identifiers as a guaranteed list.
     *
     * @return list<string>
     */
    private static function permissionIds(mixed $permissions): array
    {
        if (! $permissions instanceof Collection) {
            return [];
        }

        $identifiers = [];

        foreach ($permissions as $permission) {
            if ($permission instanceof Permission) {
                $identifiers[] = $permission->id;
            }
        }

        sort($identifiers, SORT_STRING);

        return $identifiers;
    }

    /**
     * Normalize an aggregate count with an optional loaded-ID fallback.
     *
     * @param  list<string>  $fallback
     */
    private static function count(mixed $value, array $fallback = []): int
    {
        return is_numeric($value) ? (int) $value : count($fallback);
    }

    /**
     * Require the selected catalog timestamp and make it immutable.
     */
    private static function createdAt(mixed $value): CarbonImmutable
    {
        if (! $value instanceof DateTimeInterface) {
            throw new LogicException('Role catalog projections must select created_at.');
        }

        return CarbonImmutable::instance($value);
    }
}
