<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Passkey;

/**
 * Defines the revoke passkey use-case boundary.
 *
 * @api
 */
interface RevokePasskeyContract
{
    /**
     * Revoke an owned passkey idempotently.
     */
    public function execute(Authenticatable $subject, Passkey $passkey): Passkey;
}
