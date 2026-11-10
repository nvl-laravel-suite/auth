<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Recipient and purpose input for requesting a security code.
 *
 * @api
 */
final class RequestSecurityCodeData
{
    public function __construct(
        public readonly string $recipient,
        public readonly string $purpose,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient' => ['required', 'string', 'max:255'],
            'purpose' => ['required', 'string', 'max:255'],
        ];
    }
}
