<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Publishes one successful package authentication.
 */
final class UserAuthenticated implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create an authentication event.
     */
    public function __construct(public readonly SubjectReference $subject) {}
}
