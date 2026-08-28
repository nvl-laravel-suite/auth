<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Collection;
use LogicException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\LiteralTypeScriptType;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Bounded role catalog row containing only allowlisted assignment identifiers.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class RoleListItemData extends Data
{
    use DataTransform;

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
        #[LiteralTypeScriptType('Array<string>')]
        public readonly array $permissionIds,
        public readonly int $permissionsCount,
        public readonly int $usersCount,
        #[LiteralTypeScriptType('string')]
        public readonly CarbonImmutable $createdAt,
    ) {
        $label = trim($label);
        $this->label = $label !== '' ? $label : $name;
    }

    /**
     * Build a catalog row without triggering relationship queries.
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
