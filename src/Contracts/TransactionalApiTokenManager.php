<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;

/**
 * Participates in the source transaction of a complete token authentication.
 *
 * @api
 */
interface TransactionalApiTokenManager extends ApiTokenManager
{
    /** Return the connection on which every token issuance write participates in outer transactions. */
    public function connection(Authenticatable $subject): Connection;
}
