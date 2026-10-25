<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Results\IssuedApiToken;

/**
 * Fails closed until the host configures an API-token provider adapter.
 */
final class UnavailableApiTokenManager implements ApiTokenManager
{
    /** {@inheritDoc}
     * @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}>
     */
    public function list(Authenticatable $subject): array
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc}
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function create(Authenticatable $subject, array $data): IssuedApiToken
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc}
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     * @return array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}
     */
    public function update(Authenticatable $subject, string $tokenId, array $data): array
    {
        throw $this->unavailable();
    }

    /** {@inheritDoc}
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function rotate(Authenticatable $subject, string $tokenId, array $data): IssuedApiToken
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
        return AuthException::invalidConfiguration('API tokens require a configured ApiTokenManager such as SanctumApiTokenManager.');
    }
}
