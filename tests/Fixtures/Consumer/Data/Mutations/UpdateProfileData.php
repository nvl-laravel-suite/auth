<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Validated sparse self-service principal profile mutation.
 *
 * @api
 */
final class UpdateProfileData
{
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
        ];
    }
}
