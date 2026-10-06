<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ConfirmPasswordData;
use SensitiveParameter;

/**
 * Defines the confirm password use-case boundary.
 *
 * @api
 */
interface ConfirmPasswordContract
{
    /**
     * Verify the current password and timestamp the active session.
     */
    public function execute(
        Authenticatable $subject,
        #[SensitiveParameter] ConfirmPasswordData $data,
    ): void;
}
