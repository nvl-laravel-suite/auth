<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use PDO;

/**
 * Real commits with no wrapping transaction, for tests of races, browser state and commit hooks.
 *
 * A committed test reuses the schema the previous test left clean when it was migrated with the
 * same configuration, and clears its rows afterwards. The schema is rebuilt otherwise, and
 * after a test that changes the schema or the migration records, or replaces the connection.
 *
 * @mixin TestCase
 */
trait CommitsTestDatabase
{
    /**
     * @var array{
     *     key: string,
     *     tables: list<string>,
     *     delete_order: list<string>,
     *     can_delete: bool,
     *     sequences: list<string>,
     *     has_sqlite_sequence: bool,
     * }|null
     */
    private static ?array $committedCatalog = null;

    public function refreshDatabase(): void
    {
        $connection = $this->app->make('db')->connection();
        $connectionName = $connection->getName();
        $inMemory = $connection->getDriverName() === 'sqlite' && $connection->getDatabaseName() === ':memory:';
        if (! $inMemory && preg_match('/\A(?:nvl_auth_s04_[a-z0-9_]+|nvl_auth_test_[a-f0-9]{8}_ci)\z/', $connection->getDatabaseName()) !== 1) {
            throw new \RuntimeException('Committed tests require an explicitly disposable nvl_auth_s04_ database.');
        }

        $configuration = $this->migrationConfiguration();
        $canReuse = RefreshDatabaseState::$migrated
            && self::$migratedConfiguration === $configuration
            && ! in_array('fresh-schema', $this->groups(), true)
            && (! $inMemory || ($connectionName !== null && isset(RefreshDatabaseState::$inMemoryConnections[$connectionName])));

        if ($canReuse && $inMemory && $connectionName !== null) {
            $cachedPdo = RefreshDatabaseState::$inMemoryConnections[$connectionName];
            $connection->setPdo($cachedPdo)->setReadPdo($cachedPdo);
        } elseif (! $canReuse) {
            $this->migrateDatabases();
            $this->app[Kernel::class]->setArtisan(null);
            self::$committedCatalog = null;
            if ($inMemory && $connectionName !== null) {
                RefreshDatabaseState::$inMemoryConnections[$connectionName] = $connection->getPdo();
            }
        }

        RefreshDatabaseState::$migrated = true;
        self::$migratedConfiguration = $configuration;
        $session = $connection->getPdo();
        $schemaChanged = false;
        $connection->beforeExecuting(static function (string $query) use (&$schemaChanged): void {
            if (preg_match('/\A\s*(?:create|alter|drop|rename|attach|detach)\s|\A\s*(?:insert\s+into|update|delete\s+from)\s+\W?migrations\b/i', $query) === 1) {
                $schemaChanged = true;
            }
        });
        $this->beforeApplicationDestroyed(function () use ($connection, $connectionName, $inMemory, $session, $configuration, &$schemaChanged): void {
            if ($schemaChanged || $this->app->make('db')->connection() !== $connection || $connection->getRawPdo() !== $session) {
                RefreshDatabaseState::$migrated = false;
                self::$committedCatalog = null;
                if ($inMemory && $connectionName !== null) {
                    unset(RefreshDatabaseState::$inMemoryConnections[$connectionName]);
                }

                return;
            }
            if (! $this->clearCommittedRows($connection, $session, $configuration)) {
                RefreshDatabaseState::$migrated = false;
                self::$committedCatalog = null;
                if ($inMemory && $connectionName !== null) {
                    unset(RefreshDatabaseState::$inMemoryConnections[$connectionName]);
                }
            }
        });
    }

    private function clearCommittedRows(Connection $connection, PDO $pdo, string $configuration): bool
    {
        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        $migrations = $connection->getTablePrefix().config('database.migrations.table', 'migrations');
        $driver = $connection->getDriverName();
        $catalogKey = $driver.':'.$connection->getDatabaseName().':'.$migrations.':'.$configuration;

        if ($driver === 'pgsql') {
            return $this->clearPostgresCommittedRows($pdo, $migrations, $catalogKey);
        }

        if ($driver === 'sqlite') {
            return $this->clearSqliteCommittedRows($pdo, $migrations, $catalogKey);
        }

        $schema = $connection->getSchemaBuilder();
        $schema->withoutForeignKeyConstraints(static function () use ($connection, $schema, $migrations): void {
            $schemas = $schema->getCurrentSchemaListing();
            $tables = array_diff(array_column($schema->getTables($schemas), 'name'), [$migrations]);
            foreach ($tables as $table) {
                if ($connection->table($table)->exists()) {
                    $connection->table($table)->truncate();
                }
            }
        });

        return true;
    }

    private function clearPostgresCommittedRows(PDO $pdo, string $migrations, string $catalogKey): bool
    {
        if ((self::$committedCatalog['key'] ?? null) !== $catalogKey) {
            self::$committedCatalog = $this->buildPostgresCommittedCatalog($pdo, $migrations, $catalogKey);
        }

        $catalog = self::$committedCatalog;
        if ($catalog['tables'] === []) {
            return true;
        }

        $probes = [];
        foreach ($catalog['delete_order'] as $index => $table) {
            $probes[] = "select 't' as k, {$index} as idx where exists (select 1 from ".$this->quoteCommittedPostgresIdentifier($table).')';
        }
        foreach ($catalog['sequences'] as $index => $sequence) {
            $probes[] = "select 's' as k, {$index} as idx from ".$this->quoteCommittedPostgresIdentifier($sequence).' where is_called or last_value <> 1';
        }

        if ($probes === []) {
            return true;
        }

        $dirtyTables = [];
        $dirtySequences = [];
        foreach ($pdo->query(implode(' union all ', $probes))->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $idx = (int) $row['idx'];
            if ($row['k'] === 't') {
                $dirtyTables[] = $catalog['delete_order'][$idx];
            } else {
                $dirtySequences[] = $catalog['sequences'][$idx];
            }
        }

        if ($dirtyTables === [] && $dirtySequences === []) {
            return true;
        }

        if ($catalog['can_delete']) {
            $statements = [];
            foreach ($dirtyTables as $table) {
                $statements[] = 'delete from '.$this->quoteCommittedPostgresIdentifier($table);
            }
            foreach ($dirtySequences as $sequence) {
                $statements[] = 'select setval('.$pdo->quote($this->quoteCommittedPostgresIdentifier($sequence)).', 1, false)';
            }

            try {
                $pdo->exec(implode('; ', $statements));

                return true;
            } catch (\Throwable) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
            }
        }

        try {
            $wrapped = array_map($this->quoteCommittedPostgresIdentifier(...), $catalog['tables']);
            $pdo->exec('truncate table '.implode(', ', $wrapped).' restart identity cascade');

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private function clearSqliteCommittedRows(PDO $pdo, string $migrations, string $catalogKey): bool
    {
        if ((self::$committedCatalog['key'] ?? null) !== $catalogKey) {
            self::$committedCatalog = $this->buildSqliteCommittedCatalog($pdo, $migrations, $catalogKey);
        }

        $catalog = self::$committedCatalog;
        if ($catalog['tables'] === []) {
            return true;
        }

        $probes = [];
        foreach ($catalog['delete_order'] as $index => $table) {
            $probes[] = "select {$index} as idx where exists (select 1 from ".$this->quoteCommittedIdentifier($table).')';
        }

        $dirtyTables = [];
        foreach ($pdo->query(implode(' union all ', $probes))->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $dirtyTables[] = $catalog['delete_order'][(int) $row['idx']];
        }

        if ($dirtyTables === []) {
            if ($catalog['has_sqlite_sequence']) {
                $pdo->exec('delete from "sqlite_sequence" where "name" <> '.$pdo->quote($migrations));
            }

            return true;
        }

        $foreignKeys = (int) $pdo->query('pragma foreign_keys')->fetchColumn();
        try {
            $pdo->exec('pragma foreign_keys = 0');
            foreach ($dirtyTables as $table) {
                $pdo->exec('delete from '.$this->quoteCommittedIdentifier($table));
            }
            if ($catalog['has_sqlite_sequence']) {
                $pdo->exec('delete from "sqlite_sequence" where "name" <> '.$pdo->quote($migrations));
            }
        } catch (\Throwable) {
            return false;
        } finally {
            try {
                $pdo->exec('pragma foreign_keys = '.$foreignKeys);
            } catch (\Throwable) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array{key: string, tables: list<string>, delete_order: list<string>, can_delete: bool, sequences: list<string>, has_sqlite_sequence: bool}
     */
    private function buildPostgresCommittedCatalog(PDO $pdo, string $migrations, string $catalogKey): array
    {
        $tables = [];
        $hasDeleteTrigger = [];
        $rows = $pdo->query(
            "select c.relname as name, exists (select 1 from pg_trigger t where t.tgrelid = c.oid and not t.tgisinternal and (t.tgtype & 8) <> 0) as has_delete_trigger from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname",
        )->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $name = (string) $row['name'];
            if ($name === $migrations) {
                continue;
            }
            $tables[] = $name;
            $hasDeleteTrigger[$name] = (bool) $row['has_delete_trigger'];
        }

        $tableSet = array_fill_keys($tables, true);
        $edges = array_fill_keys($tables, []);
        $inDegree = array_fill_keys($tables, 0);

        $fkRows = $pdo->query(
            "select child.relname as child_table, parent.relname as parent_table, con.confdeltype as del_type from pg_constraint con join pg_class child on child.oid = con.conrelid join pg_namespace cn on cn.oid = child.relnamespace join pg_class parent on parent.oid = con.confrelid join pg_namespace pn on pn.oid = parent.relnamespace where con.contype = 'f' and cn.nspname = 'public' and pn.nspname = 'public' and child.oid <> parent.oid",
        )->fetchAll(PDO::FETCH_ASSOC);

        foreach ($fkRows as $row) {
            $child = (string) $row['child_table'];
            $parent = (string) $row['parent_table'];
            if (! isset($tableSet[$child], $tableSet[$parent])) {
                continue;
            }
            $first = ($hasDeleteTrigger[$child] && $row['del_type'] === 'c') ? $parent : $child;
            $second = $first === $parent ? $child : $parent;
            if (! isset($edges[$first][$second])) {
                $edges[$first][$second] = true;
                $inDegree[$second]++;
            }
        }

        $queue = [];
        foreach ($tables as $table) {
            if ($inDegree[$table] === 0) {
                $queue[] = $table;
            }
        }

        $deleteOrder = [];
        while ($queue !== []) {
            $current = array_shift($queue);
            $deleteOrder[] = $current;
            foreach (array_keys($edges[$current]) as $next) {
                $inDegree[$next]--;
                if ($inDegree[$next] === 0) {
                    $queue[] = $next;
                }
            }
        }

        $canDelete = count($deleteOrder) === count($tables);
        if (! $canDelete) {
            $deleteOrder = $tables;
        }

        $sequences = [];
        $seqRows = $pdo->query(
            "select distinct s.relname as name, tbl.relname as owner_table from pg_class s join pg_namespace sn on sn.oid = s.relnamespace left join pg_depend d on d.classid = 'pg_class'::regclass and d.objid = s.oid and d.refclassid = 'pg_class'::regclass and d.deptype in ('a', 'i') left join pg_class tbl on tbl.oid = d.refobjid where sn.nspname = 'public' and s.relkind = 'S' order by s.relname",
        )->fetchAll(PDO::FETCH_ASSOC);

        foreach ($seqRows as $row) {
            if (($row['owner_table'] ?? null) === $migrations) {
                continue;
            }
            $sequences[] = (string) $row['name'];
        }

        return [
            'key' => $catalogKey,
            'tables' => $tables,
            'delete_order' => $deleteOrder,
            'can_delete' => $canDelete,
            'sequences' => array_values(array_unique($sequences)),
            'has_sqlite_sequence' => false,
        ];
    }

    /**
     * @return array{key: string, tables: list<string>, delete_order: list<string>, can_delete: bool, sequences: list<string>, has_sqlite_sequence: bool}
     */
    private function buildSqliteCommittedCatalog(PDO $pdo, string $migrations, string $catalogKey): array
    {
        $tables = [];
        $triggerTables = [];
        $hasSqliteSequence = false;

        $rows = $pdo->query("select type, name, tbl_name, sql from sqlite_master where type in ('table', 'trigger')")->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            $name = (string) $row['name'];
            if ($row['type'] === 'table') {
                if ($name === 'sqlite_sequence') {
                    $hasSqliteSequence = true;

                    continue;
                }
                if (str_starts_with($name, 'sqlite_') || $name === $migrations) {
                    continue;
                }
                $tables[] = $name;
            } elseif (is_string($row['sql'] ?? null) && stripos($row['sql'], 'before delete') !== false) {
                $triggerTables[(string) $row['tbl_name']] = true;
            }
        }

        sort($tables);
        $first = [];
        $last = [];
        foreach ($tables as $table) {
            if (isset($triggerTables[$table])) {
                $last[] = $table;
            } else {
                $first[] = $table;
            }
        }

        return [
            'key' => $catalogKey,
            'tables' => $tables,
            'delete_order' => [...$first, ...$last],
            'can_delete' => true,
            'sequences' => [],
            'has_sqlite_sequence' => $hasSqliteSequence,
        ];
    }

    private function quoteCommittedPostgresIdentifier(string $identifier): string
    {
        return '"public".'.$this->quoteCommittedIdentifier($identifier);
    }

    private function quoteCommittedIdentifier(string $identifier): string
    {
        return '"'.str_replace('"', '""', $identifier).'"';
    }
}
