<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

/**
 * Resolves configured package principals consistently, including restoration flows.
 */
final readonly class UserLocator
{
    /**
     * Create the principal locator.
     */
    public function __construct(private AuthModelRegistry $models) {}

    /**
     * Start a query for the configured principal model.
     *
     * @return Builder<User>
     */
    public function query(bool $withTrashed = false): Builder
    {
        $class = $this->models->userClass();
        $query = $class::query();

        return $withTrashed ? $query->withTrashed() : $query;
    }

    /**
     * Resolve a principal model or identifier.
     */
    public function find(User|string $user, bool $withTrashed = false): User
    {
        if ($user instanceof User) {
            return $user;
        }

        return $this->query($withTrashed)->findOrFail($user);
    }

    /**
     * Require an authenticated principal backed by the configured package model.
     */
    public function authenticated(Authenticatable $subject): User
    {
        $class = $this->models->userClass();

        if (! $subject instanceof $class) {
            throw AuthException::invalidConfiguration(
                "Principal management requires authenticated users to extend [{$class}].",
            );
        }

        return $subject;
    }
}
