<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\VerifySecurityCodeData;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/**
 * Defines the verify security code authentication use-case boundary.
 *
 * @api
 */
interface VerifySecurityCodeAuthenticationContract
{
    /** Verify a passwordless code and establish the referenced subject session. */
    public function execute(
        VerifySecurityCodeData $data,
        AuthenticationRequestContext $requestContext,
    ): Challenge;
}
