<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Resolves package references to fixture users.
 */
final class TestSubjectResolver implements AuthSubjectResolver
{
    /**
     * Resolve one fixture user.
     */
    public function resolve(SubjectReference $reference): ?Authenticatable
    {
        if ($reference->type !== (new TestUser)->getMorphClass()) {
            return null;
        }

        return TestUser::query()->find($reference->identifier);
    }
}
