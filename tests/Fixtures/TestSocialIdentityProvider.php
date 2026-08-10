<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use RuntimeException;

/**
 * Provides verified external identity claims for social integration tests.
 */
final class TestSocialIdentityProvider implements SocialIdentityProvider
{
    /**
     * Create the controllable social-provider fixture.
     */
    public function __construct(
        private readonly bool $failRedirect = false,
        private readonly bool $failUser = false,
    ) {}

    /** {@inheritDoc} */
    public function redirectUrl(
        string $provider,
        ?string $callbackUrl,
        array $scopes,
        array $parameters,
    ): string {
        if ($this->failRedirect) {
            throw new RuntimeException('fixture redirect credential leaked');
        }

        return "https://provider.example/authorize/{$provider}";
    }

    /** {@inheritDoc} */
    public function user(string $provider, ?string $callbackUrl): ExternalIdentity
    {
        if ($this->failUser) {
            throw new RuntimeException('fixture callback credential leaked');
        }

        return new ExternalIdentity(
            provider: $provider,
            providerUserId: 'provider-user-123',
            email: 'claim@example.test',
            name: 'External User',
            profile: ['source' => 'test'],
            emailVerified: true,
            emailVerificationSource: 'fixture.email_verified',
        );
    }
}
