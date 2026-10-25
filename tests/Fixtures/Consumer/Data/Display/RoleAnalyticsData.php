<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\LiteralTypeScriptType;

/**
 * Bounded, identity-free per-role analytics with deterministic permission groups.
 *
 * @api
 */
#[MapOutputName(CamelCaseMapper::class)]
final class RoleAnalyticsData extends Data
{
    /** @var array<string, int> */
    #[LiteralTypeScriptType('Record<string, number>')]
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
}
