<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Subject identifier input for requesting a password reset.
 *
 * @api
 */
final class RequestPasswordResetData
{
    public function __construct(
        public readonly string $identifier,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'identifier' => ['required', 'string', 'max:255'],
        ];
    }
}
