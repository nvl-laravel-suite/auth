<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/** Validated active-state mutation for an authentication client. */
final class UpdateClientStatusData
{
    public function __construct(
        public readonly bool $active,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'active' => ['required', 'boolean'],
        ];
    }
}
