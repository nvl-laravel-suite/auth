<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Invitation;

/** Returns the atomically consumed invitation and registered subject. */
final readonly class InvitationRegistrationResult
{
    /** Create the registration result. */
    public function __construct(
        public Invitation $invitation,
        public Authenticatable $subject,
    ) {}
}
