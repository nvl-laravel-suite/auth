<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * TOTP verification code input for authentication.
 *
 * @api
 */
final class VerifyTotpData
{
    public function __construct(
        public readonly string $code,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'code' => ['required', 'string', 'max:20'],
        ];
    }
}
