<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Support\Facades\DB;
use RuntimeException;
use Throwable;

/** Runs bounded membership workers against independent database connections. */
final class AuthMembershipRace
{
    /**
     * @param  list<callable(): array<string, mixed>>  $workers
     * @return list<array{ok: bool, error?: class-string, code?: string}>
     */
    public static function run(string $connectionName, array $workers): array
    {
        $configuration = config("database.connections.{$connectionName}");
        if (! is_array($configuration)) {
            throw new RuntimeException('The Auth membership race connection is unavailable.');
        }
        $gate = tempnam(sys_get_temp_dir(), 'auth-membership-gate-');
        $ready = array_map(static fn (int $index): string|false => tempnam(sys_get_temp_dir(), "auth-membership-ready-{$index}-"), array_keys($workers));
        $results = array_map(static fn (int $index): string|false => tempnam(sys_get_temp_dir(), "auth-membership-result-{$index}-"), array_keys($workers));
        if (! is_string($gate) || in_array(false, $ready, true) || in_array(false, $results, true)) {
            throw new RuntimeException('The Auth membership race could not allocate IPC files.');
        }
        /** @var list<non-falsy-string> $ready */
        /** @var list<non-falsy-string> $results */
        $children = [];
        try {
            foreach ($workers as $index => $worker) {
                $pid = pcntl_fork();
                if ($pid === -1) {
                    throw new RuntimeException('The Auth membership race could not fork.');
                }
                if ($pid > 0) {
                    $children[] = $pid;

                    continue;
                }
                try {
                    config()->set("database.connections.{$connectionName}", $configuration);
                    DB::purge($connectionName);
                    file_put_contents($ready[$index], 'ready');
                    $deadline = microtime(true) + 10;
                    while (file_get_contents($gate) !== 'go') {
                        if (microtime(true) >= $deadline) {
                            throw new RuntimeException('The Auth membership race gate timed out.');
                        }
                        usleep(10_000);
                    }
                    $result = ['ok' => true, ...$worker()];
                } catch (Throwable $exception) {
                    $result = [
                        'ok' => false,
                        'error' => $exception::class,
                        'code' => property_exists($exception, 'errorCode') ? $exception->errorCode : null,
                    ];
                }
                file_put_contents($results[$index], json_encode($result, JSON_THROW_ON_ERROR));
                exit(0);
            }
            self::waitReady($ready);
            file_put_contents($gate, 'go');
            foreach ($children as $child) {
                $status = 0;
                pcntl_waitpid($child, $status);
                if (! pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0) {
                    throw new RuntimeException('An Auth membership race worker failed.');
                }
            }

            return array_map(static function (string $path): array {
                $result = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
                if (! is_array($result) || ! is_bool($result['ok'] ?? null)) {
                    throw new RuntimeException('An Auth membership race result is invalid.');
                }

                return $result;
            }, $results);
        } finally {
            foreach ([$gate, ...$ready, ...$results] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
        }
    }

    /** @param list<string> $paths */
    private static function waitReady(array $paths): void
    {
        $deadline = microtime(true) + 10;
        do {
            if (array_all($paths, static fn (string $path): bool => file_get_contents($path) === 'ready')) {
                return;
            }
            usleep(10_000);
        } while (microtime(true) < $deadline);

        throw new RuntimeException('Auth membership race workers did not become ready.');
    }
}
