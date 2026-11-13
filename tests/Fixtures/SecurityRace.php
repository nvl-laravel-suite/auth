<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Closure;
use Illuminate\Support\Facades\DB;
use PDO;
use RuntimeException;
use Throwable;

/** Independent committed connections with bounded process coordination. */
final class SecurityRace
{
    /** @param list<Closure(): array<string, mixed>> $workers
     * @return list<array<string, mixed>> */
    public static function run(array $workers): array
    {
        $driver = DB::connection()->getDriverName();
        if ($driver !== 'pgsql' || DB::connection()->transactionLevel() !== 0) {
            throw new RuntimeException('Races require committed PostgreSQL.');
        }
        $pdoDriver = $driver;
        if (DB::connection()->getPdo()->getAttribute(PDO::ATTR_DRIVER_NAME) !== $pdoDriver) {
            throw new RuntimeException('The native race source selected an incompatible PDO driver.');
        }
        $directory = sys_get_temp_dir().'/auth-security-race-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        $children = [];
        DB::disconnect();
        try {
            foreach ($workers as $index => $worker) {
                $pid = pcntl_fork();
                if ($pid === -1) {
                    throw new RuntimeException('Could not fork security worker.');
                }
                if ($pid > 0) {
                    $children[] = $pid;

                    continue;
                }
                try {
                    DB::purge();
                    $connection = DB::connection();
                    if ($connection->getDriverName() !== $driver || $connection->transactionLevel() !== 0
                        || $connection->getPdo()->getAttribute(PDO::ATTR_DRIVER_NAME) !== $pdoDriver) {
                        throw new RuntimeException('Worker did not select committed production engine.');
                    }
                    $connectionId = $connection->scalar('SELECT pg_backend_pid()');
                    file_put_contents("{$directory}/ready-{$index}", 'ready');
                    self::wait(static fn (): bool => is_file("{$directory}/go"));
                    $result = ['ok' => true, 'driver' => $driver, 'pdo_driver' => $pdoDriver, 'process_id' => getmypid(), 'connection_id' => $connectionId, ...$worker()];
                } catch (Throwable $exception) {
                    $result = ['ok' => false, 'error' => $exception::class, 'message' => $exception->getMessage()];
                }
                file_put_contents("{$directory}/result-{$index}", json_encode($result, JSON_THROW_ON_ERROR));
                if (is_executable('/usr/bin/true')) {
                    pcntl_exec('/usr/bin/true');
                }
                pcntl_exec(PHP_BINARY, ['-n', '-r', 'exit(0);']);
                exit(1);
            }
            self::wait(static fn (): bool => count(glob("{$directory}/ready-*") ?: []) === count($workers));
            file_put_contents("{$directory}/go", 'go');
            self::wait(static fn (): bool => count(glob("{$directory}/result-*") ?: []) === count($workers));
            $results = [];
            foreach ($children as $index => $pid) {
                pcntl_waitpid($pid, $status);
                $decoded = json_decode((string) file_get_contents("{$directory}/result-{$index}"), true, flags: JSON_THROW_ON_ERROR);
                if (! is_array($decoded)) {
                    throw new RuntimeException('A security worker returned an invalid result.');
                }
                $result = [];
                foreach ($decoded as $key => $value) {
                    if (! is_string($key)) {
                        throw new RuntimeException('A security worker returned an invalid result key.');
                    }
                    $result[$key] = $value;
                }
                $results[] = $result;
            }

            return $results;
        } finally {
            foreach ($children as $pid) {
                if (pcntl_waitpid($pid, $status, WNOHANG) === 0) {
                    posix_kill($pid, SIGKILL);
                    pcntl_waitpid($pid, $status);
                }
            }
            foreach (glob("{$directory}/*") ?: [] as $file) {
                unlink($file);
            }
            rmdir($directory);
        }
    }

    /** Wait for IPC, never indefinitely. */
    public static function wait(Closure $ready): void
    {
        $deadline = microtime(true) + 15;
        while (! $ready()) {
            if (microtime(true) > $deadline) {
                throw new RuntimeException('Security race IPC timed out.');
            }
            usleep(10000);
        }
    }
}
