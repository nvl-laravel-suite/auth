<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

/**
 * Provides a host permission policy for embedded-application adapter tests.
 */
final class EmbeddedPermissionPolicy
{
    /**
     * Grant aggregate permission management to the fixture manager.
     */
    public function manage(TestUser $actor): bool
    {
        return $actor->email === 'manager@example.test';
    }
}
