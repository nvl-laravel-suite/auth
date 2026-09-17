<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use InvalidArgumentException;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Data;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[TypeScript]
/** Selects the recipient and revision for an ownership transfer. */
final class TransferMembershipOwnershipData extends Data
{
    use DataTransform;

    public function __construct(public readonly string $recipientMembershipId, public readonly int $expectedRevision)
    {
        if (! preg_match('/^[0-9a-f-]{36}$/i', $this->recipientMembershipId) || $this->expectedRevision < 1) {
            throw new InvalidArgumentException('Ownership transfer input is invalid.');
        }
    }
}
