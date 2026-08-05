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
final class FinishPasskeyAuthenticationData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>  $response
     */
    public function __construct(
        public readonly string $ceremonyId,
        public readonly array $response,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'response' => ['required', 'array'],
        ];
    }
}
