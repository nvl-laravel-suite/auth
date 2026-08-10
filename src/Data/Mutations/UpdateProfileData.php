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
use Spatie\LaravelData\Optional;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated sparse self-service principal profile mutation. */
final class UpdateProfileData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>|Optional  $profile
     * @param  array<string, mixed>|Optional  $preferences
     */
    public function __construct(
        public readonly string|Optional $name = new Optional,
        public readonly string|Optional $email = new Optional,
        public readonly string|Optional $locale = new Optional,
        public readonly string|Optional $timezone = new Optional,
        public readonly array|Optional $profile = new Optional,
        public readonly array|Optional $preferences = new Optional,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string|Optional $currentPassword = new Optional,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'name' => ['sometimes', 'string', 'max:160'],
            'email' => ['sometimes', 'email:rfc', 'max:320'],
            'locale' => ['sometimes', 'string', 'regex:/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/'],
            'timezone' => ['sometimes', 'timezone:all'],
            'profile' => ['sometimes', 'array'],
            'preferences' => ['sometimes', 'array'],
            'currentPassword' => ['sometimes', 'string', 'max:4096'],
        ];
    }
}
