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
        if ($driver !== 'pgsql') {
            return;
        }

        $config = $app['config'];
        $key = "database.connections.{$driver}";
        $connection = is_array($config->get($key)) ? $config->get($key) : [];
        $source = [
            'driver' => $driver,
            'host' => getenv('DB_HOST') ?: ($connection['host'] ?? '127.0.0.1'),
            'port' => getenv('DB_PORT') ?: ($connection['port'] ?? '5432'),
            'database' => getenv('DB_DATABASE') ?: ($connection['database'] ?? null),
            'username' => getenv('DB_USERNAME') ?: ($connection['username'] ?? 'postgres'),
            'password' => getenv('DB_PASSWORD') !== false ? getenv('DB_PASSWORD') : ($connection['password'] ?? ''),
            'prefix' => '',
        ];
        $config->set('database.default', $driver);

        if (array_all($source, static fn (mixed $value, string $key): bool => ($connection[$key] ?? null) === $value)
            && in_array($connection['url'] ?? null, [null, ''], true)
            && in_array($connection['unix_socket'] ?? null, [null, ''], true)
            && ! isset($connection['read']) && ! isset($connection['write'])) {
            return;
        }

        unset($connection['read'], $connection['write']);
        $config->set($key, array_replace($connection, $source, ['url' => null, 'unix_socket' => '', 'charset' => 'utf8']));
    }
}
