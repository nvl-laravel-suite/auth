<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries;

use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class UserIndexQueryData extends Data
{
    public function __construct(
        public readonly ?string $search = null,
        public readonly ?bool $active = null,
        public readonly ?string $trashed = null,
        public readonly ?string $role = null,
        #[MapInputName('per_page')] #[MapOutputName('per_page')] public readonly ?int $perPage = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'search' => ['sometimes', 'string', 'max:160'],
            'active' => ['sometimes', 'boolean'],
            'trashed' => ['sometimes', 'in:without,with,only'],
            'role' => ['sometimes', 'string', 'max:160'],
            'per_page' => ['sometimes', 'integer', 'between:1,100'],
        ];
    }
}
