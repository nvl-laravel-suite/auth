<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Fails closed when reference-based login has no host resolver.
 */
final class UnavailableAuthSubjectResolver implements AuthSubjectResolver
{
    /**
     * Reject reference resolution until configured by the host.
     */
    public function resolve(SubjectReference $reference): ?Authenticatable
    {
        throw AuthException::invalidConfiguration(
            'Reference-based authentication requires an AuthSubjectResolver.',
        );
    }
}
