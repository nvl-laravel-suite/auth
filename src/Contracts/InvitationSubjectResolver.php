<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Invitation;

/**
 * Resolves or provisions the host subject consuming a public invitation.
 */
interface InvitationSubjectResolver
{
    /**
     * Resolve the invitation consumer from host-owned registration input.
     *
     * @param  array<string, mixed>  $input
     */
    public function resolve(Invitation $invitation, array $input): Authenticatable;
}
