<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ImpersonationAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Impersonation is unavailable until a consumer explicitly authorizes it. *
 * @internal
 */
final class DenyImpersonationAccess implements ImpersonationAccess
{
    public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void
    {
        throw new AuthException('impersonation_forbidden', 'Impersonation is not authorized.', 403);
    }
}
