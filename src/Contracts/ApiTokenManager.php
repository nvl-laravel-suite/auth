<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Manages provider-owned personal access tokens without Auth projections.
 */
interface ApiTokenManager
{
    /**
     * List subject-owned provider tokens.
     *
     * @return list<ApiTokenSnapshot>
     */
    public function list(Authenticatable $subject): array;

    /**
     * Issue one provider token.
     */
    public function create(Authenticatable $subject, ApiTokenData $data): IssuedApiToken;

    /**
     * Update one subject-owned provider token.
     */
    public function update(
        Authenticatable $subject,
        string $tokenId,
        ApiTokenData $data,
    ): ApiTokenSnapshot;

    /**
     * Rotate one subject-owned provider token.
     */
    public function rotate(
        Authenticatable $subject,
        string $tokenId,
        ApiTokenData $data,
    ): IssuedApiToken;

    /**
     * Revoke one subject-owned provider token.
     */
    public function revoke(Authenticatable $subject, string $tokenId): bool;

    /**
     * Revoke every subject-owned provider token.
     */
    public function revokeAll(Authenticatable $subject): int;
}
