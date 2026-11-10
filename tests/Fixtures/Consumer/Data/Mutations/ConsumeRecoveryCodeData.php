<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Recovery code input for authenticating a subject.
 *
 * @api
 */
final class ConsumeRecoveryCodeData
{
    public function __construct(
        public readonly string $code,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'code' => ['required', 'string', 'max:128'],
        ];
    }
}
