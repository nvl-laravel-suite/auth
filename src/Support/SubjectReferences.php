<?php

declare(strict_types=1);

namespace Nvl\Auth\Support;

use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Compares host subject references strictly without numeric string coercion.
 *
 * @internal
 */
final class SubjectReferences
{
    public static function same(?SubjectReference $left, ?SubjectReference $right): bool
    {
        if ($left === null || $right === null) {
            return $left === $right;
        }

        return $left->type === $right->type && $left->identifier === $right->identifier;
    }
}
