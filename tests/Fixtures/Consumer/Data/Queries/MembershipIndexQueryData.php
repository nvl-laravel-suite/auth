<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries;

/** Validated membership table search and page size. */
final class MembershipIndexQueryData
{
    public function __construct(
        public readonly ?string $search = null,
        public readonly ?int $perPage = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'search' => ['nullable', 'string', 'max:191'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
        ];
    }
}
