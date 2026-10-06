<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\VerifySecurityCodeData;
use Nvl\Auth\Models\Challenge;

/**
 * Defines the verify security code use-case boundary.
 *
 * @api
 */
interface VerifySecurityCodeContract
{
    /**
     * Consume a matching security code.
     */
    public function execute(VerifySecurityCodeData $data): Challenge;
}
