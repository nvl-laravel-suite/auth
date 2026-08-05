<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;

/**
 * Resolves identifiers through the configured Laravel guard's user provider.
 */
final readonly class LaravelGuardIdentifierResolver implements AuthIdentifierResolver
{
    /**
     * Create the Laravel user-provider adapter.
     */
    public function __construct(
        private AuthManager $auth,
        private AuthConfiguration $configuration,
    ) {}

    /** {@inheritDoc} */
    public function resolve(string $identifierName, string $identifier): ?Authenticatable
    {
        $guard = $this->auth->guard($this->configuration->string('guard', 'web'));
        $provider = $this->provider($guard);

        return $provider->retrieveByCredentials([$identifierName => $identifier]);
    }

    /**
     * Require the configured guard to expose its user provider.
     */
    private function provider(Guard $guard): UserProvider
    {
        if (! method_exists($guard, 'getProvider')) {
            throw AuthException::invalidConfiguration(
                'Identifier resolution requires a Laravel guard with a user provider.',
            );
        }

        return $guard->getProvider();
    }
}
