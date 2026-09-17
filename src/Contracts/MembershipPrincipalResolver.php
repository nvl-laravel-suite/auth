<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Resolves and validates host-owned membership principals. */
interface MembershipPrincipalResolver
{
    public function resolve(SubjectReference $reference, bool $lock = false): Authenticatable;

    public function assertEligible(Authenticatable $principal): void;

    public function connectionName(): string;
}
