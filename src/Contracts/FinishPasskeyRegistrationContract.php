<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\FinishPasskeyRegistrationData;
use Nvl\Auth\Models\Passkey;

/**
 * Defines the finish passkey registration use-case boundary.
 *
 * @api
 */
interface FinishPasskeyRegistrationContract
{
    /**
     * Verify browser response data and persist credential material.
     */
    public function execute(
        Authenticatable $subject,
        FinishPasskeyRegistrationData $data,
    ): Passkey;
}
