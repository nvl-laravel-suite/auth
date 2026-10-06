<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\ResetPasswordData;
use SensitiveParameter;

/**
 * Defines the reset password use-case boundary.
 *
 * @api
 */
interface ResetPasswordContract
{
    /**
     * Reset a host-owned password through Laravel's broker.
     */
    public function execute(#[SensitiveParameter] ResetPasswordData $data): void;
}
