<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;

/** Returns a tenant intent nonce exactly once with its bounded expiry. */
final readonly class IssuedTenantAuthenticationIntent
{
    public function __construct(
        public string $id,
        public string $nonce,
        public CarbonImmutable $expiresAt,
    ) {}
}
