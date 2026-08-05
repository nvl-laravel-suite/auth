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
final class ResetPasswordData extends Data
{
    use DataTransform;

    public function __construct(
        public readonly string $identifier,
        public readonly string $token,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $password,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $passwordConfirmation,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'identifier' => ['required', 'string', 'max:255'],
            'token' => ['required', 'string', 'max:128'],
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed'],
        ];
    }
}
