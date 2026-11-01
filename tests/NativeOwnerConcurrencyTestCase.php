<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Support\Facades\DB;
use RuntimeException;

/** Runs committed native owner races on the matrix's explicitly disposable database. */
abstract class NativeOwnerConcurrencyTestCase extends NativeOwnerScenarioTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $driver = getenv('NVL_C1_TEST_DRIVER') ?: getenv('DB_CONNECTION');
        if (! in_array($driver, ['pgsql', 'mysql', 'mariadb'], true)) {
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
            if (in_array($connection->getDriverName(), ['pgsql', 'mysql', 'mariadb'], true)) {
                $database = $connection->getDatabaseName();
                if (preg_match('/^(?:nvl_auth_test_[a-f0-9]{8}_ci|nvl_light_auth_races)$/D', $database) !== 1) {
                    throw new RuntimeException('Native Auth fixture cleanup requires its dedicated Auth database.');
                }
                $connection->getSchemaBuilder()->dropAllTables();
                $this->beforeApplicationDestroyed(static function () use ($connection, $database): void {
                    if ($connection->getDatabaseName() !== $database) {
                        throw new RuntimeException('The native Auth fixture source changed before cleanup.');
                    }
                    $connection->getSchemaBuilder()->dropAllTables();
                });
            }
        });
        parent::setUp();
    }
}
