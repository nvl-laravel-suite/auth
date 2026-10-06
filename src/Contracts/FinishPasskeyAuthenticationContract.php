<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\FinishPasskeyAuthenticationData;
use Nvl\Auth\Results\CompletedPasskeyAuthentication;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the finish passkey authentication use-case boundary.
 *
 * @api
 */
interface FinishPasskeyAuthenticationContract
{
    /** Verify a browser ceremony and recover only its server-owned tenant context. */
    public function execute(
        FinishPasskeyAuthenticationData $data,
        ?TenantId $requestedTenant = null,
    ): CompletedPasskeyAuthentication;
}
