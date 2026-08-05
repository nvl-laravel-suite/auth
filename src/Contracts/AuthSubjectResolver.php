<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Resolves a package subject reference back to its host authenticatable.
 */
interface AuthSubjectResolver
{
    /**
     * Resolve the referenced host subject or return null when unavailable.
     */
    public function resolve(SubjectReference $reference): ?Authenticatable;
}
