<?php

declare(strict_types=1);

namespace Nvl\Auth\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * Identifies the unique index a rejected write collided on.
 *
 * Index names follow the configured table name and host-created indexes may carry any name, so the
 * violated index is read from the table's own catalog instead of being assumed.
 *
 * @internal
 */
final class UniqueViolation
{
    /**
     * Return the indexed columns of the violated unique index of one table, or null when the
     * violation belongs to another table.
     *
     * @return list<string>|null
     */
    public static function columns(UniqueConstraintViolationException $exception, Connection $connection, string $table): ?array
    {
        $detail = $exception->errorInfo[2] ?? null;
        $message = is_string($detail) ? $detail : $exception->getMessage();
        [$schema, $logicalTable] = $connection->getSchemaBuilder()->parseSchemaAndTable($table);
        $unqualified = $connection->getTablePrefix().$logicalTable;
        $qualified = ($schema === null ? '' : $schema.'.').$unqualified;
        foreach ($connection->getSchemaBuilder()->getIndexes($table) as $index) {
            if (! $index['unique']) {
                continue;
            }
            $columns = $index['columns'];
            // SQLite names the columns ("UNIQUE constraint failed: table.a, table.b"); PostgreSQL names the index.
            $sqlite = 'UNIQUE constraint failed: '.implode(', ', array_map(static fn (string $column): string => "{$unqualified}.{$column}", $columns));
            $named = '/(?<![\w$.])(?:'.preg_quote($qualified, '/').'\.|'.preg_quote($unqualified, '/').'\.)?'.preg_quote($index['name'], '/').'(?![\w$])/';
            if ($connection->getDriverName() === 'sqlite' ? $message === $sqlite : preg_match($named, $message) === 1) {
                return $columns;
            }
        }

        return null;
    }
}
