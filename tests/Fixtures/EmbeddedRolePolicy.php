<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

/**
 * Provides a host role policy for embedded-application adapter tests.
 */
final class EmbeddedRolePolicy
{
    /**
     * Grant aggregate role management to the fixture manager.
     */
    public function manage(TestUser $actor): bool
    {
        return $actor->email === 'manager@example.test';
    }
}
