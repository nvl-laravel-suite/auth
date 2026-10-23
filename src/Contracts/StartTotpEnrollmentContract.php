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
     * Replace prior pending enrollments and return new provisioning material once.
     *
     * Hosts must authorize and reauthenticate the owning principal before restarting.
     * Pending secrets cannot be resumed; confirmed credentials remain unchanged.
     */
    public function execute(
        Authenticatable $subject,
        StartTotpEnrollmentData $data,
    ): TotpEnrollment;
}
