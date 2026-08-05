<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\CanResetPassword;

/**
 * Updates a host-owned password after package authorization succeeds.
 */
interface PasswordUpdater
{
    /**
     * Persist a hashed replacement password for a host subject.
     */
    public function update(CanResetPassword $subject, string $password): void;
}
