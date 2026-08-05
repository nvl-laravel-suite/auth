<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Fails closed when social login has no host subject resolver.
 */
final class UnavailableSocialSubjectResolver implements SocialSubjectResolver
{
    /**
     * Reject social login until the host supplies a resolver.
     */
    public function resolve(ExternalIdentity $identity): Authenticatable
    {
        throw AuthException::invalidConfiguration(
            'Social login requires a configured SocialSubjectResolver.',
        );
    }
}
