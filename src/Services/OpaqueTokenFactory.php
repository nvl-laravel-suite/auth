<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

/**
 * Generates high-entropy URL-safe bearer tokens.
 */
final class OpaqueTokenFactory
{
    /**
     * Generate a 256-bit URL-safe token.
     */
    public function make(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
