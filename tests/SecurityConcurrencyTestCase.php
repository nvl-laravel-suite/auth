<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

/** Committed fixtures confined to disposable test databases. */
abstract class SecurityConcurrencyTestCase extends TestCase
{
    use CommitsTestDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $driver = getenv('NVL_C1_TEST_DRIVER');
        if (in_array($driver, ['mysql', 'mariadb', 'pgsql'], true)) {
            $app['config']->set('database.default', $driver);
            $app['config']->set("database.connections.{$driver}", [
                'driver' => $driver, 'host' => getenv('DB_HOST'), 'port' => getenv('DB_PORT'),
                'database' => getenv('DB_DATABASE'), 'username' => getenv('DB_USERNAME'),
                'password' => getenv('DB_PASSWORD'), 'charset' => 'utf8', 'prefix' => '',
            ]);
        }
    }
}
