<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Connection;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Reject unsupported browser/independent-proof effects inside an enclosing transaction.
 *
 * @internal
 */
final readonly class StatefulAuthenticationBoundary
{
    public function assertOutsideTransaction(Connection $connection): void
    {
        if ($connection->transactionLevel() !== 0) {
            throw new AuthException('stateful_transaction_unsupported', 'This operation must run outside an enclosing source transaction.', 409);
        }
    }
}
