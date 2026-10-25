<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Client, flow, and return destination for starting authentication.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class StartClientAuthData extends Data
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $flow,
        public readonly string $returnPath,
        public readonly ?string $origin = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'clientId' => ['required', 'string', 'max:191'],
            'flow' => ['required', 'string'],
            'returnPath' => ['required', 'string'],
        ];
    }
}
