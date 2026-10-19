<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;

/** Returns a owner selection intent nonce exactly once with its bounded expiry. */
final readonly class IssuedOwnerAuthenticationIntent
{
    public function __construct(
        public string $id,
        public string $nonce,
        public CarbonImmutable $expiresAt,
    ) {}
}
