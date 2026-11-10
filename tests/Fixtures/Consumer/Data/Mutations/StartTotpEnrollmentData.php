<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Account and label input for starting TOTP enrollment.
 *
 * @api
 */
final class StartTotpEnrollmentData
{
    public function __construct(
        public readonly string $accountName,
        public readonly ?string $name = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'accountName' => ['required', 'string', 'max:255'],
            'name' => ['sometimes', 'nullable', 'string', 'max:120'],
        ];
    }
}
