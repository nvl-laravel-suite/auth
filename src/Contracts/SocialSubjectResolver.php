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
     * Resolve the principal for one external identity.
     *
     * Implementations matching by email must require a true emailVerified claim
     * and retain or inspect emailVerificationSource as verification provenance.
     */
    public function resolve(ExternalIdentity $identity): Authenticatable;
}
