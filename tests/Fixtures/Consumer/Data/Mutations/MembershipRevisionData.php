<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/** Exact membership revision required for revocation. */
final class MembershipRevisionData
{
    public function __construct(public readonly int $expectedRevision) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return ['expected_revision' => ['required', 'integer', 'min:1']];
    }
}
