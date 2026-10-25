<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Validated active-state mutation for a managed principal.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class UpdateUserStatusData extends Data
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
