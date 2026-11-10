<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Ceremony response and name input for registering a passkey.
 *
 * @api
 */
final class FinishPasskeyRegistrationData
{
    /**
     * @param  array<string, mixed>  $response
     */
    public function __construct(
        public readonly string $ceremonyId,
        public readonly array $response,
        public readonly ?string $name = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'ceremonyId' => ['required', 'string', 'max:191'],
            'response' => ['required', 'array'],
            'name' => ['sometimes', 'nullable', 'string', 'max:120'],
        ];
    }
}
