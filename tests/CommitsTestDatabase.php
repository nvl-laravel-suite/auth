<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\RefreshDatabaseState;

/**
 * Real commits with no wrapping transaction, for tests of races, browser state and commit hooks.
 *
 * A committed test reuses the schema the previous test left clean when it was migrated with the
 * same configuration, and truncates its rows afterwards. The schema is rebuilt otherwise, and
 * after a test that changes the schema or the migration records, or replaces the connection. In-memory SQLite keeps
 * rebuilding per test, which costs nothing there.
 *
 * @mixin TestCase
 */
trait CommitsTestDatabase
{
    public function refreshDatabase(): void
    {
        $connection = $this->app->make('db')->connection();
        $inMemory = $connection->getDriverName() === 'sqlite' && $connection->getDatabaseName() === ':memory:';
        if (! $inMemory && preg_match('/\A(?:nvl_auth_s04_[a-z0-9_]+|nvl_auth_test_[a-f0-9]{8}_ci)\z/', $connection->getDatabaseName()) !== 1) {
            throw new \RuntimeException('Committed tests require an explicitly disposable nvl_auth_s04_ database.');
        }
        $configuration = $this->migrationConfiguration();
        if ($inMemory || ! RefreshDatabaseState::$migrated || self::$migratedConfiguration !== $configuration) {
            $this->artisan('migrate:fresh', $this->migrateFreshUsing());
            $this->app[Kernel::class]->setArtisan(null);
        }
        RefreshDatabaseState::$migrated = ! $inMemory;
        self::$migratedConfiguration = $configuration;
        $schemaChanged = false;
        $connection->beforeExecuting(static function (string $query) use (&$schemaChanged): void {
            if (preg_match('/\A\s*(?:create|alter|drop|rename)\s|\A\s*(?:insert\s+into|update|delete\s+from)\s+\W?migrations\b/i', $query) === 1) {
                $schemaChanged = true;
            }
        });
        $this->beforeApplicationDestroyed(function () use ($connection, $inMemory, &$schemaChanged): void {
            if ($inMemory || $schemaChanged || $this->app->make('db')->connection() !== $connection) {
                RefreshDatabaseState::$migrated = false;

                return;
            }
            $this->truncateCommittedRows($connection);
        });
    }

    private function truncateCommittedRows(Connection $connection): void
    {
        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
        $schema = $connection->getSchemaBuilder();
        $migrations = $connection->getTablePrefix().config('database.migrations.table', 'migrations');
        $schema->withoutForeignKeyConstraints(static function () use ($connection, $schema, $migrations): void {
            foreach ($schema->getTables($schema->getCurrentSchemaListing()) as $table) {
                if ($table['name'] !== $migrations && $connection->table($table['name'])->exists()) {
                    $connection->table($table['name'])->truncate();
                }
            }
        });
    }
}
