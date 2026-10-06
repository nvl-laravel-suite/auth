<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the request security code authentication use-case boundary.
 *
 * @api
 */
interface RequestSecurityCodeAuthenticationContract
{
    public function execute(
        RequestSecurityCodeData $data,
        ?string $locale = null,
        ?TenantId $tenant = null,
    ): ?IssuedChallenge;
}
