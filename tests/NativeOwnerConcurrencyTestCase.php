<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/** Runs committed native owner races on the matrix's explicitly disposable database. */
abstract class NativeOwnerConcurrencyTestCase extends NativeOwnerScenarioTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $driver = getenv('NVL_C1_TEST_DRIVER') ?: getenv('DB_CONNECTION');
        if ($driver !== 'pgsql') {
            return;
        }
        $database = getenv('DB_DATABASE');
        if (! is_string($database) || preg_match('/^(?:nvl_auth_test_[a-f0-9]{8}_ci|nvl_light_auth_races)$/D', $database) !== 1) {
            throw new RuntimeException('Native Auth races require an explicitly disposable Auth database.');
        }
        $app['config']->set('database.default', $driver);
        $app['config']->set('database.connections.'.$driver.'.url', null);
        $app['config']->set('database.connections.'.$driver.'.database', $database);
    }

    protected function setUp(): void
    {
        $this->afterApplicationCreated(function (): void {
            $connection = DB::connection();
            if ($connection->getDriverName() === 'pgsql') {
                $database = $connection->getDatabaseName();
                if (preg_match('/^(?:nvl_auth_test_[a-f0-9]{8}_ci|nvl_light_auth_races)$/D', $database) !== 1) {
                    throw new RuntimeException('Native Auth fixture cleanup requires its dedicated Auth database.');
                }
                RefreshDatabaseState::$migrated = false;
                $connection->getSchemaBuilder()->dropAllTables();
                $this->beforeApplicationDestroyed(static function () use ($connection, $database): void {
                    if ($connection->getDatabaseName() !== $database) {
                        throw new RuntimeException('The native Auth fixture source changed before cleanup.');
                    }
                    RefreshDatabaseState::$migrated = false;
                    $connection->getSchemaBuilder()->dropAllTables();
                });
            }
        });
        parent::setUp();
    }
}
