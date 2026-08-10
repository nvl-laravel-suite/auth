<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;
use InvalidArgumentException;

/**
 * Carries trusted host issuance policy that must never be hydrated from public input.
 */
final readonly class InvitationIssuanceContext
{
    /** Create a bounded host issuance context. */
    public function __construct(
        public bool $actorlessAuthorized = false,
        public ?CarbonImmutable $expiresAt = null,
        public ?string $returnPath = null,
    ) {
        if ($this->expiresAt !== null
            && (! $this->expiresAt->isFuture() || $this->expiresAt->isAfter(CarbonImmutable::now()->addYear()))) {
            throw new InvalidArgumentException('Invitation expiry overrides must be future dates within one year.');
        }

        if ($this->returnPath !== null
            && (trim($this->returnPath) === '' || mb_strlen($this->returnPath) > 1_024)) {
            throw new InvalidArgumentException('Invitation return paths must contain between one and 1,024 characters.');
        }
    }
}
