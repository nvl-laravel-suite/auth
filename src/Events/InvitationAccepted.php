<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Publishes one privacy-bounded invitation acceptance after storage commits.
 */
final class InvitationAccepted implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create the committed invitation acceptance event.
     */
    public function __construct(
        public readonly string $invitationId,
        public readonly string $type,
        public readonly string $purpose,
        public readonly SubjectReference $subject,
    ) {}
}
