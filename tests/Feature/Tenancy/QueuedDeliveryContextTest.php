<?php

declare(strict_types=1);

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Process;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Enums\TenantContextMode;

it('captures queued delivery tenancy before a later context change', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $reference = SubjectReference::fromAuthenticatable($owner);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);

    $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('invited@example.test'),
        $owner,
    ));
    $scenario->run($scenario->b(), static fn (): bool => true);
    /** @var AuthDeliveryRequested $event */
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    /** @var AuthDeliveryRequested $restored */
    $restored = unserialize(serialize($event), ['allowed_classes' => true]);

    expect($restored->tenantJobEnvelope()->context->mode)->toBe(TenantContextMode::Tenant)
        ->and($restored->tenantJobEnvelope()->context->tenantId?->value)->toBe($scenario->a()->value)
        ->and($restored->request->tenant?->value)->toBe($scenario->a()->value);
});

it('restores delivery context in a genuine database worker and clears it between retries', function (): void {
    $root = dirname(__DIR__, 6);
    $consumer = sys_get_temp_dir().'/nvl-auth-worker-'.bin2hex(random_bytes(8));
    $files = new Filesystem;

    try {
        $files->copyDirectory($root.'/vendor/orchestra/testbench-core/laravel', $consumer);
        $files->cleanDirectory($consumer.'/bootstrap/cache');
        symlink($root.'/vendor', $consumer.'/vendor');
        touch($consumer.'/database/queue.sqlite');
        $bootstrap = <<<'PHP'
<?php
return Illuminate\Foundation\Application::configure(basePath: dirname(__DIR__))
    ->withProviders([
        Nvl\Support\Providers\SupportServiceProvider::class,
        Nvl\Data\Providers\DataServiceProvider::class,
        Nvl\Tenancy\Providers\TenancyServiceProvider::class,
        Nvl\Auth\Tests\Fixtures\AuthDeliveryWorkerProvider::class,
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
        ];
        $seed = Process::path($consumer)->env($environment)->timeout(30)->run([
            PHP_BINARY,
            dirname(__DIR__, 2).'/Fixtures/auth-delivery-worker-seed.php',
            $consumer,
        ]);
        expect($seed->successful())->toBeTrue($seed->output().$seed->errorOutput());

        $worker = Process::path($consumer)->env($environment)->timeout(30)->run([
            PHP_BINARY,
            $consumer.'/artisan',
            'queue:work',
            '--stop-when-empty',
            '--tries=2',
            '--backoff=0',
            '--sleep=0',
            '--no-interaction',
        ]);
        expect($worker->successful())->toBeTrue($worker->output().$worker->errorOutput());

        config(['database.connections.auth_worker_receipts' => [
            'driver' => 'sqlite',
            'database' => $consumer.'/database/queue.sqlite',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]]);
        $database = DB::connection('auth_worker_receipts');
        $receipts = $database->table('nvl_auth_test_delivery_receipts')
            ->orderBy('tenant_id')->orderBy('attempt')->orderBy('id')->get()
            ->map(static fn (object $receipt): array => [
                'tenant_id' => $receipt->tenant_id,
                'message_id' => $receipt->message_id,
                'attempt' => $receipt->attempt,
            ])->all();
        $failures = $database->table('failed_jobs')->orderBy('id')->pluck('exception')->all();
        expect($receipts)->toBe([
            ['tenant_id' => AuthTenancyScenario::A, 'message_id' => 'delivery-a', 'attempt' => 1],
            ['tenant_id' => AuthTenancyScenario::A, 'message_id' => 'delivery-a', 'attempt' => 10],
            ['tenant_id' => AuthTenancyScenario::A, 'message_id' => 'delivery-a', 'attempt' => 11],
            ['tenant_id' => AuthTenancyScenario::B, 'message_id' => 'delivery-b', 'attempt' => 1],
        ], implode("\n---\n", $failures).$worker->output().$worker->errorOutput())->and($database->table('nvl_auth_test_worker_scopes')->distinct()->pluck('mode')->all())
            ->toBe(['unresolved'])
            ->and($database->table('jobs')->count())->toBe(0);
    } finally {
        DB::purge('auth_worker_receipts');
        $files->deleteDirectory($consumer);
    }
});
