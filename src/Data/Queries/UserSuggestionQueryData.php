<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Queries;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class UserSuggestionQueryData extends Data
{
    use DataTransform;

    public function __construct(
        public readonly string $search,
        public readonly ?int $limit = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'search' => ['required', 'string', 'min:1', 'max:160'],
            'limit' => ['sometimes', 'integer', 'between:1,100'],
        ];
    }
}
