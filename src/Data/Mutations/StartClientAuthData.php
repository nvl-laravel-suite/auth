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
final class StartClientAuthData extends Data
{
    use DataTransform;

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
