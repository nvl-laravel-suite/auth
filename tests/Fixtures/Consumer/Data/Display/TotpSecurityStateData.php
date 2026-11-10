<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * Describes principal TOTP lifecycle counts without credentials or provisioning secrets.
 *
 * @api
 */
final class TotpSecurityStateData implements Arrayable, JsonSerializable
{
    /** Retain disjoint lifecycle counts, treating every revoked credential as revoked. */
    public function __construct(
        public readonly int $confirmedCredentials,
        public readonly int $pendingEnrollments,
        public readonly int $revokedCredentials,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'confirmedCredentials' => $this->confirmedCredentials,
            'pendingEnrollments' => $this->pendingEnrollments,
            'revokedCredentials' => $this->revokedCredentials,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
