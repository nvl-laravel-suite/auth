<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Resolves social test claims to one fixture host user.
 */
final readonly class TestSocialSubjectResolver implements SocialSubjectResolver
{
    public function __construct(private TestUser $user) {}

    /** {@inheritDoc} */
    public function resolve(ExternalIdentity $identity): Authenticatable
    {
        return $this->user;
    }
}
