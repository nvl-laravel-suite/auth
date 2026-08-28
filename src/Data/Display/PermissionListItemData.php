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
 * Bounded permission catalog row containing only allowlisted assignment identifiers.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class PermissionListItemData extends Data
{
    use DataTransform;

    public readonly string $label;

    public readonly string $group;

    /**
     * Create a permission catalog projection.
     *
     * @param  list<string>  $roleIds
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        string $label,
        public readonly ?string $description,
        public readonly string $guard,
        string $group,
        #[LiteralTypeScriptType('Array<string>')]
        public readonly array $roleIds,
        public readonly int $rolesCount,
        public readonly int $usersCount,
        #[LiteralTypeScriptType('string')]
        public readonly CarbonImmutable $createdAt,
    ) {
        $label = trim($label);
        $this->label = $label !== '' ? $label : $name;
        $this->group = PermissionOptionData::normalizeGroup($group);
    }

    /**
     * Build a catalog row without triggering relationship queries.
     */
    public static function fromModel(Permission $permission): self
    {
        $roles = $permission->relationLoaded('roles')
            ? $permission->getRelation('roles')
            : null;
        $roleIds = self::roleIds($roles);

        return new self(
            id: $permission->id,
            name: $permission->name,
            label: $permission->display_name ?? '',
            description: $permission->description,
            guard: $permission->guard_name,
            group: $permission->group ?? '',
            roleIds: $roleIds,
            rolesCount: self::count($permission->getAttribute('roles_count'), $roleIds),
            usersCount: self::count($permission->getAttribute('users_count')),
            createdAt: self::createdAt($permission->getAttribute('created_at')),
        );
    }

    /**
     * Extract loaded role identifiers as a guaranteed list.
     *
     * @return list<string>
     */
    private static function roleIds(mixed $roles): array
    {
        if (! $roles instanceof Collection) {
            return [];
        }

        $identifiers = [];

        foreach ($roles as $role) {
            if ($role instanceof Role) {
                $identifiers[] = $role->id;
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
            throw new LogicException('Permission catalog projections must select created_at.');
        }

        return CarbonImmutable::instance($value);
    }
}
