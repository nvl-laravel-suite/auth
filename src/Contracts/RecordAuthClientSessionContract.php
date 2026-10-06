<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Models\AuthClientSession;

/**
 * Defines the record auth client session use-case boundary.
 *
 * @api
 */
interface RecordAuthClientSessionContract
{
    /**
     * Create or refresh one client-session correlation record.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function execute(
        AuthClient $client,
        string $sessionId,
        ?Authenticatable $subject = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        array $metadata = [],
    ): AuthClientSession;
}
