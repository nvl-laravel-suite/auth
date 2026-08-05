<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Exceptions\AuthException;

/**
 * Produces purpose-separated blind indexes for package secrets and identifiers.
 */
final readonly class SecretHasher
{
    /**
     * Hash one value for an explicit package purpose.
     */
    public function hash(string $purpose, string $value): string
    {
        $key = config('app.key');

        if (! is_string($key) || trim($key) === '') {
            throw AuthException::invalidConfiguration(
                'Auth secret hashing requires a configured application key.',
            );
        }

        return hash_hmac('sha256', $purpose."\0".$value, $key);
    }
}
