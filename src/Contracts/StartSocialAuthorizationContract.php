<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the start social authorization use-case boundary.
 *
 * @api
 */
interface StartSocialAuthorizationContract
{
    /**
     * Return the provider redirect URL.
     */
    public function execute(
        string $provider,
        ?TenantId $tenant = null,
        ?string $returnPath = null,
    ): string;
}
