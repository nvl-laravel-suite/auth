<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Resolves an existing configured principal after verified social authentication.
 *
 * @api
 */
interface SocialSubjectResolver
{
    /**
     * Resolve an existing canonical principal for one external identity.
     * Raw or quiet provisioning is outside this resolver contract.
     *
     * Implementations matching by email must require a true emailVerified claim
     * and retain or inspect emailVerificationSource as verification provenance.
     */
    public function resolve(ExternalIdentity $identity): Authenticatable;
}
