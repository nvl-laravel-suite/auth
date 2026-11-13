<?php

declare(strict_types=1);

use Illuminate\Database\SQLiteConnection;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Process\Factory;
use PHPUnit\Framework\TestCase;

uses(TestCase::class);

it('restores delivery context in a genuine database worker and clears it between retries', function (): void {
    $root = is_dir(dirname(__DIR__, 2).'/vendor/orchestra/testbench-core/laravel')
        ? dirname(__DIR__, 2)
        : dirname(__DIR__, 5);
    $consumer = sys_get_temp_dir().'/nvl-auth-worker-'.bin2hex(random_bytes(8));
    $files = new Filesystem;
    $processes = new Factory;
    $database = null;

    try {
        $files->copyDirectory($root.'/vendor/orchestra/testbench-core/laravel', $consumer);
        $files->cleanDirectory($consumer.'/bootstrap/cache');
        symlink($root.'/vendor', $consumer.'/vendor');
        touch($consumer.'/database/queue.sqlite');
        $bootstrap = <<<'PHP'
<?php
return Illuminate\Foundation\Application::configure(basePath: dirname(__DIR__))
    ->withProviders([
        Nvl\Support\Providers\LocaleServiceProvider::class, Nvl\Support\Providers\SupportServiceProvider::class,
        Nvl\Auth\Tests\Fixtures\AuthDeliveryWorkerProvider::class,
        Nvl\Ownership\Providers\OwnershipServiceProvider::class,
    ])->withExceptions()->withMiddleware()->create();
PHP;
        file_put_contents($consumer.'/bootstrap/app.php', $bootstrap);
        file_put_contents($consumer.'/bootstrap/cache/packages.php', '<?php return [];');
        $environment = [
            'APP_ENV' => 'testing',
            'APP_KEY' => 'base64:'.base64_encode(str_repeat('a', 32)),
            'DB_CONNECTION' => 'sqlite',
            'DB_DATABASE' => $consumer.'/database/queue.sqlite',
            'DB_URL' => '',
            'CACHE_STORE' => 'array',
            'QUEUE_CONNECTION' => 'database',
            'APP_PACKAGES_CACHE' => $consumer.'/bootstrap/cache/packages.php',
            'APP_SERVICES_CACHE' => $consumer.'/bootstrap/cache/services.php',
            'XDEBUG_MODE' => 'off',
        ];
        $seed = $processes->path($consumer)->env($environment)->timeout(30)->run([
            PHP_BINARY,
            '-d',
            'opcache.enable_cli=1',
            dirname(__DIR__).'/Fixtures/auth-delivery-worker-seed.php',
            $consumer,
        ]);
        expect($seed->successful())->toBeTrue($seed->output().$seed->errorOutput());

        $worker = $processes->path($consumer)->env($environment)->timeout(30)->run([
            PHP_BINARY,
            '-d',
            'opcache.enable_cli=1',
            $consumer.'/artisan',
            'queue:work',
            '--stop-when-empty',
            '--tries=2',
            '--backoff=0',
            '--sleep=0',
            '--no-interaction',
        ]);
        expect($worker->successful())->toBeTrue($worker->output().$worker->errorOutput());

        $queueDatabase = $consumer.'/database/queue.sqlite';
        $database = new SQLiteConnection(new PDO('sqlite:'.$queueDatabase), $queueDatabase);
        $receipts = $database->table('nvl_auth_test_delivery_receipts')
            ->orderBy('owner_key')->orderBy('attempt')->orderBy('id')->get()
            ->map(static fn (object $receipt): array => [
                'owner_key' => $receipt->owner_key,
                'message_id' => $receipt->message_id,
                'attempt' => $receipt->attempt,
            ])->all();
        $failures = $database->table('failed_jobs')->orderBy('id')->pluck('exception')->all();
        expect($receipts)->toBe([
            ['owner_key' => '7', 'message_id' => 'delivery-a', 'attempt' => 1],
            ['owner_key' => '7', 'message_id' => 'delivery-a', 'attempt' => 10],
            ['owner_key' => '7', 'message_id' => 'delivery-a', 'attempt' => 11],
            ['owner_key' => '8', 'message_id' => 'delivery-b', 'attempt' => 1],
        ], implode("\n---\n", $failures).$worker->output().$worker->errorOutput())->and($database->table('nvl_auth_test_worker_scopes')->distinct()->pluck('mode')->all())
            ->toBe(['unresolved'])
            ->and($database->table('jobs')->count())->toBe(0);
    } finally {
        $database?->disconnect();
        $files->deleteDirectory($consumer);
    }
});
