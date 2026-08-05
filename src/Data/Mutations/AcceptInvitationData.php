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
final class AcceptInvitationData extends Data
{
    use DataTransform;

    /** Create a validated invitation-acceptance mutation. */
    public function __construct(
        public readonly string $token,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $password,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $passwordConfirmation,
        public readonly string $name,
        public readonly ?string $locale = null,
        public readonly ?string $timezone = null,
    ) {}

    /** @return array<string, string|null> */
    public function toRegistrationArray(): array
    {
        return [
            'password' => $this->password,
            'password_confirmation' => $this->passwordConfirmation,
            'name' => $this->name,
            'locale' => $this->locale,
            'timezone' => $this->timezone,
        ];
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:128'],
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed'],
            'name' => ['required', 'string', 'max:160'],
            'locale' => ['sometimes', 'nullable', 'string', 'max:12'],
            'timezone' => ['sometimes', 'nullable', 'timezone:all'],
        ];
    }
}
