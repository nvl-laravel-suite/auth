<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Fails closed until the host configures an API-token provider adapter.
 */
final class UnavailableApiTokenManager implements ApiTokenManager
{
    /** {@inheritDoc} */
    public function list(Authenticatable $subject): array
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc} */
    public function create(Authenticatable $subject, ApiTokenData $data): IssuedApiToken
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc} */
    public function update(Authenticatable $subject, string $tokenId, ApiTokenData $data): ApiTokenSnapshot
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc} */
    public function rotate(Authenticatable $subject, string $tokenId, ApiTokenData $data): IssuedApiToken
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc} */
    public function revoke(Authenticatable $subject, string $tokenId): bool
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc} */
    public function revokeAll(Authenticatable $subject): int
    {
        throw $this->unavailable();
    }

    /**
     * Build the configuration failure.
     */
    private function unavailable(): AuthException
    {
        return AuthException::invalidConfiguration(
            'API tokens require a configured ApiTokenManager such as SanctumApiTokenManager.',
        );
    }
}
