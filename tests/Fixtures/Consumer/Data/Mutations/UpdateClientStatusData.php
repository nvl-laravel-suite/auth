<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
/** Validated active-state mutation for an authentication client. */
final class UpdateClientStatusData extends Data
{
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
