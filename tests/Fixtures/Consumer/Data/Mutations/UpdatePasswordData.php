<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use SensitiveParameter;

/**
 * Current and replacement sensitive passwords for a password change.
 *
 * @api
 */
final class UpdatePasswordData
{
    public function __construct(
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
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed:passwordConfirmation'],
        ];
    }
}
