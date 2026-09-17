<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;

/** Refuses tenant invitation acceptance until recipient proof is configured. */
final readonly class DisabledInvitationRecipientProof implements InvitationRecipientProof
{
    public function assertMatches(Invitation $invitation, Authenticatable $subject): void
    {
        throw AuthException::invalidConfiguration('The tenant invitation recipient proof is disabled.');
    }
}
