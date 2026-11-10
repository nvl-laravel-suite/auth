<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use SensitiveParameter;

/**
 * Token and sensitive password input for resetting a password.
 *
 * @api
 */
final class ResetPasswordData
{
    public function __construct(
        public readonly string $identifier,
        public readonly string $token,
        #[SensitiveParameter]
        public readonly string $password,
        #[SensitiveParameter]
        public readonly string $passwordConfirmation,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'passwordConfirmation' => ['required', 'string'],
            'identifier' => ['required', 'string', 'max:255'],
            'token' => ['required', 'string', 'max:128'],
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed:passwordConfirmation'],
        ];
    }
}
