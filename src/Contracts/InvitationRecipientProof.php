<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Invitation;

/** Proves that an authenticated principal owns the invited mailbox. */
interface InvitationRecipientProof
{
    public function assertMatches(Invitation $invitation, Authenticatable $subject): void;
}
