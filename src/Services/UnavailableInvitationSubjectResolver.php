<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;

/**
 * Fails closed until the host supplies invitation registration behavior.
 */
final class UnavailableInvitationSubjectResolver implements InvitationSubjectResolver
{
    /**
     * Reject public invitation acceptance without a host subject resolver.
     */
    public function resolve(Invitation $invitation, array $input): Authenticatable
    {
        throw AuthException::invalidConfiguration(
            'Public invitation acceptance requires an InvitationSubjectResolver.',
        );
    }
}
