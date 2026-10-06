<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\TotpCredential;

/**
 * Defines the revoke totp credential use-case boundary.
 *
 * @api
 */
interface RevokeTotpCredentialContract
{
    /**
     * Revoke an owned credential idempotently.
     */
    public function execute(
        Authenticatable $subject,
        TotpCredential $credential,
    ): TotpCredential;
}
