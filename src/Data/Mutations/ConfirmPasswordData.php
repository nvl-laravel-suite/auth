<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Nvl\Data\Traits\DataTransform;
use SensitiveParameter;
use Spatie\LaravelData\Attributes\Hidden;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class ConfirmPasswordData extends Data
{
    use DataTransform;

    public function __construct(
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $password,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'password' => ['required', 'string', 'max:4096'],
        ];
    }
}
