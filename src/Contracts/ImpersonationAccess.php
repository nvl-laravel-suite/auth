<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Consumer authorization checked at grant creation and every effective-identity overlay.
 *
 * @api
 */
interface ImpersonationAccess
{
    public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void;
}
