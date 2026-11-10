<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Ceremony response input for completing passkey authentication.
 *
 * @api
 */
final class FinishPasskeyAuthenticationData
{
    /**
     * @param  array<string, mixed>  $response
     */
    public function __construct(
        public readonly string $ceremonyId,
        public readonly array $response,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'ceremonyId' => ['required', 'string'],
            'response' => ['required', 'array'],
        ];
    }
}
