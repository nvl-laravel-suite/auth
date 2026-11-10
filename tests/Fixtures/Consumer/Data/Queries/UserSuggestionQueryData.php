<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries;

final class UserSuggestionQueryData
{
    public function __construct(
        public readonly string $search,
        public readonly ?int $limit = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'search' => ['required', 'string', 'min:1', 'max:160'],
            'limit' => ['sometimes', 'integer', 'between:1,100'],
        ];
    }
}
