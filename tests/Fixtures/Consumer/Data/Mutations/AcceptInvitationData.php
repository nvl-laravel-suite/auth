<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use SensitiveParameter;

/**
 * Registration input for accepting an invitation.
 *
 * @api
 */
final class AcceptInvitationData
{
    /** Create a validated invitation-acceptance mutation. */
    public function __construct(
        public readonly string $token,
        public readonly string $name,
        public readonly string $registrationMethod = 'password',
        #[SensitiveParameter]
        public readonly ?string $password = null,
        #[SensitiveParameter]
        public readonly ?string $passwordConfirmation = null,
        public readonly ?string $locale = null,
        public readonly ?string $timezone = null,
        /** @var array<string, mixed> */
        public readonly array $extensions = [],
    ) {}

    /** @return array<string, mixed> */
    public function toRegistrationArray(): array
    {
        $validated = [
            'name' => $this->name,
            'registrationMethod' => $this->registrationMethod,
            'locale' => $this->locale,
            'timezone' => $this->timezone,
            'extensions' => $this->extensions,
        ];

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
            'passwordConfirmation' => ['sometimes', 'nullable', 'string'],
            'token' => ['required', 'string', 'max:128'],
            'registrationMethod' => ['sometimes', 'in:password,social'],
            'password' => ['required_unless:registrationMethod,social', 'nullable', 'string', 'min:8', 'max:4096', 'confirmed:passwordConfirmation'],
            'name' => ['required', 'string', 'max:160'],
            'locale' => ['sometimes', 'nullable', 'string', 'max:12'],
            'timezone' => ['sometimes', 'nullable', 'timezone:all'],
            'extensions' => ['sometimes', 'array'],
        ];
    }
}
