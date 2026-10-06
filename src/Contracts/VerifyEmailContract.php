<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;

/**
 * Defines the verify email use-case boundary.
 *
 * @api
 */
interface VerifyEmailContract
{
    /**
     * Mark the subject's email as verified idempotently.
     */
    public function execute(Authenticatable&MustVerifyEmail $subject): bool;
}
