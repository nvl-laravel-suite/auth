<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/** Selected token adapter capability for global native security revocation.
 * Preserve consumer credentials; include managed tokens across all owners.
 *
 * @api
 */
interface SecurityTokenContainment extends TransactionalApiTokenManager
{
    /** Revoke only this adapter's package-managed tokens for the canonical principal. */
    public function revokeForSecurity(Authenticatable $subject): int;
}
