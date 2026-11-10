<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Recipient and secret input for consuming a magic-link challenge.
 *
 * @api
 */
final class ConsumeMagicLinkData
{
    public function __construct(
        public readonly ?string $recipient,
        public readonly string $token,
        public readonly ?string $challengeId = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:255'],
            'recipient' => ['required_without:challengeId', 'email:rfc', 'max:320'],
            'challengeId' => ['required_without:recipient', 'uuid'],
        ];
    }
}
