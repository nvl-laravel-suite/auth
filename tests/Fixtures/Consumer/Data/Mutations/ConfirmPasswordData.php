<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use SensitiveParameter;

/**
 * Sensitive password input for confirming the authenticated subject.
 *
 * @api
 */
final class ConfirmPasswordData
{
    public function __construct(
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
