<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Data;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[TypeScript]
/** Exposes only tenant-safe membership and allowlisted principal identity fields. */
final class TenantMembershipData extends Data
{
    use DataTransform;

    public function __construct(
        public readonly string $id,
        public readonly string $tenantId,
        public readonly string $subjectType,
        public readonly string $subjectId,
        public readonly MembershipStatus $status,
        public readonly bool $owner,
        public readonly int $revision,
        public readonly ?string $name = null,
        public readonly ?string $email = null,
    ) {}
}
