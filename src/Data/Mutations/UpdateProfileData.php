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
final class UpdateProfileData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>  $profile
     * @param  array<string, mixed>  $preferences
     */
    public function __construct(
        public readonly string $name,
        public readonly string $locale,
        public readonly string $timezone,
        public readonly array $profile = [],
        public readonly array $preferences = [],
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:160'],
            'locale' => ['required', 'string', 'regex:/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/'],
            'timezone' => ['required', 'timezone:all'],
            'profile' => ['sometimes', 'array'],
            'preferences' => ['sometimes', 'array'],
        ];
    }
}
