<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Validated self-service account deletion confirmation.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class DeleteOwnAccountData extends Data
{
    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [];
    }
}
