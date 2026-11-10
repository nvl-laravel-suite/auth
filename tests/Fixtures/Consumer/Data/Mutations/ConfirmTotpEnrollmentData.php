<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Verification code for confirming a TOTP enrollment.
 *
 * @api
 */
final class ConfirmTotpEnrollmentData
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
