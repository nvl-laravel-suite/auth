<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use InvalidArgumentException;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Data;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[TypeScript]
/** Describes one optimistic membership status mutation. */
final class UpdateMembershipStatusData extends Data
{
    use DataTransform;

    public function __construct(public readonly MembershipStatus $status, public readonly int $expectedRevision)
    {
        if ($this->expectedRevision < 1) {
            throw new InvalidArgumentException('Membership revision must be positive.');
        }
    }
}
