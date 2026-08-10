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
final class AcceptInvitationData extends Data
{
    use DataTransform;

    /** Create a validated invitation-acceptance mutation. */
    public function __construct(
        public readonly string $token,
        public readonly string $name,
        public readonly string $registrationMethod = 'password',
        #[Hidden]
        #[SensitiveParameter]
        public readonly string|null|Optional $password = new Optional,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string|null|Optional $passwordConfirmation = new Optional,
        public readonly ?string $locale = null,
        public readonly ?string $timezone = null,
        /** @var array<string, mixed> */
        public readonly array $extensions = [],
    ) {}

    /** @return array<string, mixed> */
    public function toRegistrationArray(): array
    {
        $validated = $this->except('token')->toArray();

        if (is_string($this->password)) {
            $validated['password'] = $this->password;
        }

        if (is_string($this->passwordConfirmation)) {
            $validated['password_confirmation'] = $this->passwordConfirmation;
        }

        return $validated;
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:128'],
            'registrationMethod' => ['sometimes', 'in:password,social'],
            'password' => ['required_unless:registrationMethod,social', 'nullable', 'string', 'min:8', 'max:4096', 'confirmed'],
            'name' => ['required', 'string', 'max:160'],
            'locale' => ['sometimes', 'nullable', 'string', 'max:12'],
            'timezone' => ['sometimes', 'nullable', 'timezone:all'],
            'extensions' => ['sometimes', 'array'],
        ];
    }
}
