<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Testing\PendingCommand;

/** Committed fixtures confined to disposable test databases. */
abstract class SecurityConcurrencyTestCase extends TestCase
{
    public function refreshDatabase(): void
    {
        $connection = app('db')->connection();
        if (! ($connection->getDriverName() === 'sqlite' && $connection->getDatabaseName() === ':memory:')
            && ! preg_match('/\A(?:nvl_auth_s04_[a-z0-9_]+|nvl_auth_test_[a-f0-9]{8}_ci)\z/', $connection->getDatabaseName())) {
            throw new \RuntimeException('Security races require an explicitly disposable nvl_auth_s04_ database.');
        }
        $migration = $this->artisan('migrate:fresh', ['--force' => true]);
        if ($migration instanceof PendingCommand) {
            $migration->assertSuccessful();
        } else {
            $this->assertSame(0, $migration);
        }
        $this->beforeApplicationDestroyed(static function (): void {
            RefreshDatabaseState::$migrated = false;
        });
    }

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
