<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Queries;

use InvalidArgumentException;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class RoleIndexQueryData extends Data
{
    use DataTransform;

    /** @var list<string> */
    private const array SORTS = ['name', 'label', 'priority', 'created_at'];

    /** @var list<string> */
    private const array DIRECTIONS = ['asc', 'desc'];

    public function __construct(
        public readonly ?string $search = null,
        public readonly ?int $perPage = null,
        public readonly ?bool $isSystem = null,
        public readonly ?string $guard = null,
        public readonly ?string $sort = null,
        public readonly ?string $direction = null,
        public readonly bool $includeAssignments = false,
    ) {
        if ($sort !== null && ! in_array($sort, self::SORTS, true)) {
            throw new InvalidArgumentException('The role catalog sort is not supported.');
        }

        if ($direction !== null && ! in_array($direction, self::DIRECTIONS, true)) {
            throw new InvalidArgumentException('The role catalog direction is not supported.');
        }
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'search' => ['sometimes', 'string', 'max:160'],
            'perPage' => ['sometimes', 'integer', 'between:1,100'],
            'isSystem' => ['sometimes', 'boolean'],
            'guard' => ['sometimes', 'string', 'max:120'],
            'sort' => ['sometimes', 'string', 'in:name,label,priority,created_at'],
            'direction' => ['sometimes', 'string', 'in:asc,desc'],
            'includeAssignments' => ['sometimes', 'boolean'],
        ];
    }
}
