<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

/**
 * Provides a host user policy with class-level and subject-level decisions.
 */
final class EmbeddedUserPolicy
{
    /**
     * Grant principal discovery to the fixture manager.
     */
    public function viewAny(TestUser $actor): bool
    {
        return $actor->email === 'manager@example.test';
    }

    /**
     * Grant mutation only for the expected fixture subject.
     */
    public function manage(TestUser $actor, TestUser $target): bool
    {
        return $actor->email === 'manager@example.test'
            && $target->email === 'managed@example.test';
    }
}
