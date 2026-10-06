<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Results\GeneratedRecoveryCodes;

/**
 * Defines the regenerate recovery codes use-case boundary.
 *
 * @api
 */
interface RegenerateRecoveryCodesContract
{
    /**
     * Generate and persist one new recovery-code batch.
     */
    public function execute(Authenticatable $subject): GeneratedRecoveryCodes;
}
