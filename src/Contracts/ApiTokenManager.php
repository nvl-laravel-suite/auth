<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Results\IssuedApiToken;

/**
 * Manages provider-owned personal access tokens without Auth projections.
 *
 * @api
 */
interface ApiTokenManager
{
    /**
     * List subject-owned provider tokens.
     *
     * @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}>
     */
    public function list(Authenticatable $subject): array;

    /**
     * Issue one provider token.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function create(Authenticatable $subject, array $data): IssuedApiToken;

    /**
     * Update one subject-owned provider token.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     * @return array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}
     */
    public function update(Authenticatable $subject, string $tokenId, array $data): array;

    /**
     * Rotate one subject-owned provider token.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function rotate(Authenticatable $subject, string $tokenId, array $data): IssuedApiToken;

    /**
     * Revoke one subject-owned provider token.
     */
    public function revoke(Authenticatable $subject, string $tokenId): bool;

    /**
     * Revoke every subject-owned provider token.
     */
    public function revokeAll(Authenticatable $subject): int;
}
