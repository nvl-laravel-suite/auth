<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Describes principal TOTP lifecycle counts without credentials or provisioning secrets.
 *
 * @api
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class TotpSecurityStateData extends Data
{
    use DataTransform;

    /** Retain disjoint lifecycle counts, treating every revoked credential as revoked. */
    public function __construct(
        public readonly int $confirmedCredentials,
        public readonly int $pendingEnrollments,
        public readonly int $revokedCredentials,
    ) {}
}
