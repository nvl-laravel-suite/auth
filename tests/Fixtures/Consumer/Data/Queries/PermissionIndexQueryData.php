<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries;

use InvalidArgumentException;

/**
 * Validated filtering, sorting, and pagination for permission listing.
 *
 * @api
 */
final class PermissionIndexQueryData
{
    /** @var list<string> */
    private const array SORTS = ['name', 'label', 'group', 'created_at'];

    /** @var list<string> */
    private const array DIRECTIONS = ['asc', 'desc'];

    public function __construct(
        public readonly ?string $search = null,
        public readonly ?string $group = null,
        public readonly ?int $perPage = null,
        public readonly ?string $guard = null,
        public readonly ?string $sort = null,
        public readonly ?string $direction = null,
        public readonly bool $includeAssignments = false,
    ) {
        if ($sort !== null && ! in_array($sort, self::SORTS, true)) {
            throw new InvalidArgumentException('The permission catalog sort is not supported.');
        }

        if ($direction !== null && ! in_array($direction, self::DIRECTIONS, true)) {
            throw new InvalidArgumentException('The permission catalog direction is not supported.');
        }
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'search' => ['sometimes', 'string', 'max:160'],
            'group' => ['sometimes', 'string', 'max:120'],
            'per_page' => ['sometimes', 'integer', 'between:1,100'],
            'guard' => ['sometimes', 'string', 'max:120'],
            'sort' => ['sometimes', 'string', 'in:name,label,group,created_at'],
            'direction' => ['sometimes', 'string', 'in:asc,desc'],
            'includeAssignments' => ['sometimes', 'boolean'],
        ];
    }
}
