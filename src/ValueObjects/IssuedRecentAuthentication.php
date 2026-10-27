<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use JsonSerializable;
use SensitiveParameter;

/**
 * One-use recent-authentication grant, revealed only through an explicit secret boundary.
 *
 * @api
 */
final readonly class IssuedRecentAuthentication implements JsonSerializable
{
    public function __construct(#[SensitiveParameter] private string $proof)
    {
        if (preg_match('/\A[0-9a-f]{64}\z/', $proof) !== 1) {
            throw new \InvalidArgumentException('Invalid recent-authentication grant.');
        }
    }

    public function reveal(): string
    {
        return $this->proof;
    }

    /** @return array{proof: string} */
    public function __debugInfo(): array
    {
        return ['proof' => '[REDACTED]'];
    }

    public function jsonSerialize(): never
    {
        throw new \LogicException('Recent-authentication grants must not be serialized.');
    }

    public function __serialize(): never
    {
        throw new \LogicException('Recent-authentication grants must not be serialized.');
    }
}
