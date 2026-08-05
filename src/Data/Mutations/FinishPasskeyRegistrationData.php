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
final class FinishPasskeyRegistrationData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>  $response
     */
    public function __construct(
        public readonly string $ceremonyId,
        public readonly array $response,
        public readonly ?string $name = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'ceremonyId' => ['required', 'string', 'max:191'],
            'response' => ['required', 'array'],
            'name' => ['sometimes', 'nullable', 'string', 'max:120'],
        ];
    }
}
