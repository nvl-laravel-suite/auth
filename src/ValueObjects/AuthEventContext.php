<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Immutable event classification; carries no actor or queued execution authority.
 * @api
 */
final readonly class AuthEventContext
{
    public function __construct(public OwnershipContextMode $mode, public ?OwnerReference $owner = null)
    {
        if (($mode === OwnershipContextMode::Owner) !== ($owner !== null)) {
            throw new InvalidArgumentException('Only owned Auth facts may carry an owner reference.');
        }
    }

    public static function capture(OwnershipContext $context): self
    {
        $snapshot = $context->snapshot();

        return new self($snapshot->mode, $snapshot->owner);
    }

    /** Classify a closed global identity operation without granting central authority. */
    public static function centralIdentity(): self
    {
        return new self(OwnershipContextMode::Central);
    }
}
