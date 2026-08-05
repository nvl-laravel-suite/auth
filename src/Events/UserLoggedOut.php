<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Publishes one completed Laravel guard logout.
 */
final class UserLoggedOut
{
    use Dispatchable;

    /**
     * Create a logout event.
     */
    public function __construct(public readonly ?SubjectReference $subject) {}
}
