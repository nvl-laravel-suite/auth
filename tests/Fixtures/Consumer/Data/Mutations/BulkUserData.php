<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Illuminate\Validation\Rule;
use Nvl\Auth\Enums\UserBulkOperation;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/** Validated bounded bulk principal operation. */
#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class BulkUserData extends Data
{
    /** @param list<string> $userIds */
    public function __construct(
        public readonly UserBulkOperation $operation,
        public readonly array $userIds,
    ) {}

    /** @return array<string, mixed> */
    public static function rules(): array
    {
        return [
            'operation' => ['required', Rule::enum(UserBulkOperation::class)],
            'user_ids' => ['required', 'array', 'min:1', 'max:100'],
            'user_ids.*' => ['required', 'uuid', 'distinct'],
        ];
    }
}
