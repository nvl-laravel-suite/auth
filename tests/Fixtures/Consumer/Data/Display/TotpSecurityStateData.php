<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Describes principal TOTP lifecycle counts without credentials or provisioning secrets.
 *
 * @api
 */
#[MapOutputName(CamelCaseMapper::class)]
final class TotpSecurityStateData extends Data
{
    /** Retain disjoint lifecycle counts, treating every revoked credential as revoked. */
    public function __construct(
        public readonly int $confirmedCredentials,
        public readonly int $pendingEnrollments,
        public readonly int $revokedCredentials,
    ) {}
}
