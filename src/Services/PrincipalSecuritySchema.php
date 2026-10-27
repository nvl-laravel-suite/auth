<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Schema\Builder;
use Nvl\Auth\Definitions\Tables\AuthTables;

/** Full native subject uniqueness, including engine flags omitted by Laravel index metadata.
 *
 * @internal
 */
final class PrincipalSecuritySchema
{
    public const INDEX = 'nvl_auth_principal_security_states_subject_unique';

    /** Require the exact ordered, unconditional and immediately enforced unique index. */
    public static function indexReady(Builder $schema): bool
    {
        $index = collect($schema->getIndexes(AuthTables::PrincipalSecurityStates))->firstWhere('name', self::INDEX);
        if ($index === null || ! $index['unique'] || $index['columns'] !== ['subject_type', 'subject_id']) {
            return false;
        }
        $connection = $schema->getConnection();
        [$namespace, $table] = $schema->parseSchemaAndTable(AuthTables::PrincipalSecurityStates);
        $table = $connection->getTablePrefix().$table;

        return match ($connection->getDriverName()) {
            'pgsql' => $connection->selectFromWriteConnection(
                'select 1 from pg_index i join pg_class t on t.oid = i.indrelid join pg_namespace n on n.oid = t.relnamespace join pg_class x on x.oid = i.indexrelid where t.relname = ? and n.nspname = coalesce(?, current_schema()) and x.relname = ? and i.indisunique and i.indisvalid and i.indisready and i.indislive and i.indimmediate and i.indpred is null and i.indexprs is null and i.indnkeyatts = 2 and i.indnatts = 2',
                [$table, $namespace, self::INDEX],
            ) !== [],
            'sqlite' => $connection->selectFromWriteConnection('select 1 from pragma_index_list(?, ?) where name = ? and partial = 0', [$table, $namespace ?? 'main', self::INDEX]) !== [],
            default => true,
        };
    }
}
