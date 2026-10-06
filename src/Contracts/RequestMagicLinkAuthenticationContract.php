<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\RequestMagicLinkData;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the request magic link authentication use-case boundary.
 *
 * @api
 */
interface RequestMagicLinkAuthenticationContract
{
    /**
     * Resolve an eligible subject and issue a bound login link when one exists.
     */
    public function execute(
        RequestMagicLinkData $data,
        ?string $locale = null,
        ?TenantId $tenant = null,
    ): ?IssuedChallenge;
}
