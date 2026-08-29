<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Actions\Invitations\RecordInvitationDeliveryOutcomeAction;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\InvitationDeliveryStatus;

/**
 * Return why the process-level delivery-outcome race cannot run here.
 */
function authOutcomeConcurrencySkipReason(): ?string
{
    if (! in_array(DB::connection()->getDriverName(), ['mysql', 'pgsql'], true)) {
        return 'The process concurrency gate runs in the PostgreSQL/MySQL matrix.';
    }

    if (! function_exists('pcntl_exec')
        || ! function_exists('pcntl_fork')
        || ! function_exists('pcntl_waitpid')) {
        return 'The process concurrency gate requires pcntl.';
    }

    return null;
}

/**
 * Wait until every child process has published its ready marker.
 *
 * @param  list<string>  $paths
 */
function authOutcomeWaitForWorkers(array $paths): void
{
    $deadline = microtime(true) + 10;

    do {
        $ready = true;

        foreach ($paths as $path) {
            if (file_get_contents($path) !== 'ready') {
                $ready = false;

                break;
            }
        }

        if ($ready) {
            return;
        }

        usleep(10_000);
    } while (microtime(true) < $deadline);

    throw new RuntimeException('Concurrent Auth outcome workers did not become ready.');
}

/**
 * Run two outcome callbacks simultaneously against independent connections.
 *
 * @param  list<Closure(): array<string, mixed>>  $workers
 * @return list<array<string, mixed>>
 */
function authOutcomeRunWorkers(string $connectionName, array $workers): array
{
    $connectionConfig = config("database.connections.{$connectionName}");

    if (! is_array($connectionConfig)) {
        throw new RuntimeException('The Auth concurrency database configuration is unavailable.');
    }

    $gate = tempnam(sys_get_temp_dir(), 'auth-outcome-gate-');
    $readyFiles = [];
    $resultFiles = [];

    foreach ($workers as $_worker) {
        $readyFiles[] = tempnam(sys_get_temp_dir(), 'auth-outcome-ready-');
        $resultFiles[] = tempnam(sys_get_temp_dir(), 'auth-outcome-result-');
    }

    if (! is_string($gate)
        || in_array(false, $readyFiles, true)
        || in_array(false, $resultFiles, true)) {
        throw new RuntimeException('The Auth concurrency test could not allocate IPC files.');
    }

    /** @var list<non-falsy-string> $readyFiles */
    /** @var list<non-falsy-string> $resultFiles */
    $children = [];

    try {
        foreach ($workers as $workerIndex => $worker) {
            $workerConnectionName = "auth_outcome_worker_{$workerIndex}";
            $processId = pcntl_fork();

            if ($processId === -1) {
                throw new RuntimeException('The Auth concurrency test could not fork a worker.');
            }

            if ($processId > 0) {
                $children[] = $processId;

                continue;
            }

            try {
                config()->set(
                    "database.connections.{$workerConnectionName}",
                    $connectionConfig,
                );
                config()->set('nvl-auth.connection', $workerConnectionName);
                DB::purge($workerConnectionName);
                file_put_contents($readyFiles[$workerIndex], 'ready');
                $deadline = microtime(true) + 10;

                while (file_get_contents($gate) !== 'go') {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('The Auth concurrency gate timed out.');
                    }

                    usleep(10_000);
                }

                $result = ['ok' => true, ...$worker()];
            } catch (Throwable $exception) {
                $result = [
                    'ok' => false,
                    'error' => $exception::class,
                    'message' => $exception->getMessage(),
                ];
            }

            file_put_contents(
                $resultFiles[$workerIndex],
                json_encode($result, JSON_THROW_ON_ERROR),
            );

            if (pcntl_exec(PHP_BINARY, ['-r', 'exit(0);']) === false) {
                exit(1);
            }
        }

        authOutcomeWaitForWorkers($readyFiles);
        file_put_contents($gate, 'go');

        foreach ($children as $child) {
            $status = 0;
            pcntl_waitpid($child, $status);

            expect(pcntl_wifexited($status))->toBeTrue()
                ->and(pcntl_wexitstatus($status))->toBe(0);
        }

        /** @var list<array<string, mixed>> $results */
        $results = array_map(
            static function (string $path): array {
                $decoded = json_decode(
                    (string) file_get_contents($path),
                    true,
                    flags: JSON_THROW_ON_ERROR,
                );

                if (! is_array($decoded)) {
                    throw new RuntimeException('An Auth concurrency worker returned invalid data.');
                }

                return $decoded;
            },
            $resultFiles,
        );

        return $results;
    } finally {
        foreach ([$gate, ...$readyFiles, ...$resultFiles] as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}

it('records one result when duplicate delivery outcomes race', function (): void {
    $connectionName = config('database.default');

    if (! is_string($connectionName) || $connectionName === '') {
        throw new RuntimeException('The Auth concurrency database connection is unavailable.');
    }

    $connectionConfig = config("database.connections.{$connectionName}");

    if (! is_array($connectionConfig)) {
        throw new RuntimeException('The Auth concurrency database configuration is unavailable.');
    }

    $targetConnection = 'auth_outcome_concurrency_target';
    $originalAuthConnection = config('nvl-auth.connection');
    config()->set("database.connections.{$targetConnection}", $connectionConfig);
    config()->set('nvl-auth.connection', $targetConnection);
    DB::purge($targetConnection);
    $invitationId = Str::uuid()->toString();
    $messageId = Str::uuid()->toString();
    $occurredAt = CarbonImmutable::now()->startOfSecond();
    $connection = DB::connection($targetConnection);
    $connection->table(AuthTables::Invitations)->insert([
        'id' => $invitationId,
        'token_hash' => hash('sha256', "token:{$invitationId}"),
        'recipient' => 'concurrency@example.test',
        'recipient_hash' => hash('sha256', 'concurrency@example.test'),
        'type' => 'registration',
        'purpose' => 'registration',
        'current_delivery_message_id' => $messageId,
        'delivery_status' => InvitationDeliveryStatus::Pending->value,
        'expires_at' => $occurredAt->addHour(),
        'created_at' => $occurredAt,
        'updated_at' => $occurredAt,
    ]);

    try {
        $worker = static function () use ($invitationId, $messageId, $occurredAt): array {
            app(RecordInvitationDeliveryOutcomeAction::class)->execute(
                $invitationId,
                $messageId,
                InvitationDeliveryStatus::Failed,
                $occurredAt,
                'provider_rejected',
            );

            return ['recorded' => true];
        };
        $results = authOutcomeRunWorkers($connectionName, [$worker, $worker]);

        expect(array_filter(
            $results,
            static fn (array $result): bool => $result['ok'] !== true,
        ))->toBe([])
            ->and($connection->table(AuthTables::Invitations)
                ->where('id', $invitationId)
                ->value('delivery_status'))->toBe(InvitationDeliveryStatus::Failed->value)
            ->and($connection->table(AuthTables::Invitations)
                ->where('id', $invitationId)
                ->value('delivery_failure_code'))->toBe('provider_rejected')
            ->and($connection->table(AuthTables::Audits)
                ->where('action', 'invitation.delivery_outcome_recorded')
                ->count())->toBe(1);
    } finally {
        $connection->table(AuthTables::Audits)
            ->where('action', 'invitation.delivery_outcome_recorded')
            ->delete();
        $connection->table(AuthTables::Invitations)
            ->where('id', $invitationId)
            ->delete();
        config()->set('nvl-auth.connection', $originalAuthConnection);
        DB::purge($targetConnection);
        config()->set("database.connections.{$targetConnection}", null);
    }
})->skip(
    fn (): bool => authOutcomeConcurrencySkipReason() !== null,
    'The process concurrency gate requires PostgreSQL/MySQL and pcntl.',
);
