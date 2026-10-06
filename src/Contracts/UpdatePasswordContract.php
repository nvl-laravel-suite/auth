<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Nvl\Auth\Data\Mutations\UpdatePasswordData;
use SensitiveParameter;

/**
 * Defines the update password use-case boundary.
 *
 * @api
 */
interface UpdatePasswordContract
{
    /**
     * Verify and replace the current password.
     */
    public function execute(
        Authenticatable&CanResetPassword $subject,
        #[SensitiveParameter] UpdatePasswordData $data,
    ): void;
}
