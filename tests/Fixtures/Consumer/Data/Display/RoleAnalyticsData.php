<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * Bounded, identity-free per-role analytics with deterministic permission groups.
 *
 * @api
 */
final class RoleAnalyticsData implements Arrayable, JsonSerializable
{
    /** @var array<string, int> */
    public readonly array $permissionGroups;

    /**
     * Create a role analytics projection.
     *
     * @param  array<string, int>  $permissionGroups
     */
    public function __construct(
        public readonly string $roleId,
        public readonly int $users,
        public readonly int $activeUsers,
        public readonly int $inactiveUsers,
        public readonly int $permissions,
        public readonly int $children,
        public readonly int $descendants,
        public readonly ?string $parentName,
        array $permissionGroups,
    ) {
        $normalized = [];

        foreach ($permissionGroups as $group => $count) {
            $group = PermissionOptionData::normalizeGroup($group);
            $normalized[$group] = ($normalized[$group] ?? 0) + $count;
        }

        uksort($normalized, static function (string $left, string $right) use ($normalized): int {
            $countComparison = $normalized[$right] <=> $normalized[$left];

            return $countComparison !== 0 ? $countComparison : strcmp($left, $right);
        });

        $this->permissionGroups = $normalized;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'roleId' => $this->roleId,
            'users' => $this->users,
            'activeUsers' => $this->activeUsers,
            'inactiveUsers' => $this->inactiveUsers,
            'permissions' => $this->permissions,
            'children' => $this->children,
            'descendants' => $this->descendants,
            'parentName' => $this->parentName,
            'permissionGroups' => $this->permissionGroups,
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
            roleId: $attributes['roleId'],
            users: $attributes['users'],
            activeUsers: $attributes['activeUsers'],
            inactiveUsers: $attributes['inactiveUsers'],
            permissions: $attributes['permissions'],
            children: $attributes['children'],
            descendants: $attributes['descendants'],
            parentName: $attributes['parentName'],
            permissionGroups: $attributes['permissionGroups'],
        );
    }
}
