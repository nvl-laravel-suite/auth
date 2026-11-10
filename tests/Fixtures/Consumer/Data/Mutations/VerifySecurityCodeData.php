<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Recipient, purpose, and code input for security-code verification.
 *
 * @api
 */
final class VerifySecurityCodeData
{
    public function __construct(
        public readonly string $recipient,
        public readonly string $purpose,
        public readonly string $code,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient' => ['required', 'string', 'max:255'],
            'purpose' => ['required', 'string', 'max:255'],
            'code' => ['required', 'string', 'max:128'],
        ];
    }
}
