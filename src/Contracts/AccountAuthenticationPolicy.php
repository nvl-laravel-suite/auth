<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Additional consumer restrictions under the native credential lock.
 *
 * @api
 */
interface AccountAuthenticationPolicy
{
    public function assertRemovalAllowed(Authenticatable $subject, string $kind, string $credentialId): void;
}
