<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Results\TotpEnrollment;

/**
 * Defines the start totp enrollment use-case boundary.
 *
 * @api
 */
interface StartTotpEnrollmentContract
{
    /**
     * Create a pending TOTP credential and return its one-time secret.
     */
    public function execute(
        Authenticatable $subject,
        StartTotpEnrollmentData $data,
    ): TotpEnrollment;
}
