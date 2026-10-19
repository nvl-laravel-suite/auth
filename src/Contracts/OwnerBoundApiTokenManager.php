<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Resolves persisted token ownership independently of request or loaded token attributes.
 *
 * @api
 */
interface OwnerBoundApiTokenManager
{
    public function ownerForToken(Authenticatable $subject, string $tokenId): ?OwnerReference;
}
