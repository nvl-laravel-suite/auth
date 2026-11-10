<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use SensitiveParameter;

/**
 * Identifier, sensitive password, and session preference for a login.
 *
 * @api
 */
final class LoginData
{
    public function __construct(
        public readonly string $identifier,
        #[SensitiveParameter]
        public readonly string $password,
        public readonly bool $remember = false,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'identifier' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:4096'],
            'remember' => ['sometimes', 'boolean'],
        ];
    }
}
