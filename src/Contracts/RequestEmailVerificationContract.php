<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;

/**
 * Defines the request email verification use-case boundary.
 *
 * @api
 */
interface RequestEmailVerificationContract
{
    /**
     * Request verification for one host-owned subject.
     */
    public function execute(
        Authenticatable&MustVerifyEmail $subject,
        ?string $locale = null,
    ): void;
}
