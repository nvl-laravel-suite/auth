<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\DeleteOwnAccountData;

/**
 * Defines the delete own account use-case boundary.
 *
 * @api
 */
interface DeleteOwnAccountContract
{
    /** Delete the authenticated package principal and revoke every active credential. */
    public function execute(Authenticatable $subject, DeleteOwnAccountData $data): bool;
}
