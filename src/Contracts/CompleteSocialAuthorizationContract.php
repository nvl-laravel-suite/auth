<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/**
 * Defines the complete social authorization use-case boundary.
 *
 * @api
 */
interface CompleteSocialAuthorizationContract
{
    /**
     * Acquire provider claims and link them to a supplied or resolved host subject.
     */
    public function execute(
        string $provider,
        ?Authenticatable $subject = null,
        ?string $flowReference = null,
        ?TenantId $requestedTenant = null,
    ): SocialIdentity;
}
