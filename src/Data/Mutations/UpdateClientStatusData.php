<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated active-state mutation for an authentication client. */
final class UpdateClientStatusData extends Data
{
    use DataTransform;

    public function __construct(
        public readonly bool $active,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'active' => ['required', 'boolean'],
        ];
    }
}
