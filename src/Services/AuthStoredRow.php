<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Exceptions\AuthException;
use stdClass;

/** Validates database attribute names before hydrating a bounded Auth capability record. @internal */
final readonly class AuthStoredRow
{
    /** @return array<string, mixed> */
    public static function attributes(stdClass $row): array
    {
        $attributes = [];
        foreach (get_object_vars($row) as $column => $value) {
            if (! is_string($column)) {
                throw AuthException::invalidConfiguration('Persisted Auth columns require named attributes.');
            }
            $attributes[$column] = $value;
        }

        return $attributes;
    }
}
