<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Resolves or provisions a configured principal after verified social authentication.
 */
interface SocialSubjectResolver
{
    /**
     * Resolve the principal for one verified external identity.
     */
    public function resolve(ExternalIdentity $identity): Authenticatable;
}
