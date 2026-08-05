<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\Models\AuthClient;

/**
 * Returns a validated hosted-client authentication start target.
 */
final readonly class AuthClientStartResult
{
    /**
     * Create a client start result.
     */
    public function __construct(
        public AuthClient $client,
        public string $flow,
        public string $returnUrl,
    ) {}
}
