<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the begin passkey authentication use-case boundary.
 *
 * @api
 */
interface BeginPasskeyAuthenticationContract
{
    /**
     * Begin one passkey authentication ceremony.
     */
    public function execute(?Authenticatable $subject = null, ?TenantId $tenant = null): PasskeyCeremonyOptions;
}
