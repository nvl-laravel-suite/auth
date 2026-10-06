<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ConfirmTotpEnrollmentData;
use Nvl\Auth\Models\TotpCredential;
use SensitiveParameter;

/**
 * Defines the confirm totp enrollment use-case boundary.
 *
 * @api
 */
interface ConfirmTotpEnrollmentContract
{
    /**
     * Confirm an owned pending credential.
     */
    public function execute(
        Authenticatable $subject,
        TotpCredential $credential,
        #[SensitiveParameter] ConfirmTotpEnrollmentData $data,
    ): TotpCredential;
}
