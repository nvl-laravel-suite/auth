<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the complete pending tenant authentication intent use-case boundary.
 *
 * @api
 */
interface CompletePendingTenantAuthenticationIntentContract
{
    /** Consume the authenticated session's pending intent for the expected tenant. */
    public function execute(?TenantId $expectedTenant): TenantId;
}
