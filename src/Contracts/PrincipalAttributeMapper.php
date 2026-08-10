<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Models\User;

/** Maps package principal semantics onto a configured host model schema. */
interface PrincipalAttributeMapper
{
    public function column(PrincipalAttribute $attribute): string;

    public function identifierColumn(string $configuredIdentifier): string;

    /**
     * @param  array<string, mixed>  $canonicalAttributes
     * @return array<string, mixed>
     */
    public function map(array $canonicalAttributes): array;

    public function value(User $principal, PrincipalAttribute $attribute): mixed;

    public function identifier(User $principal): string;
}
