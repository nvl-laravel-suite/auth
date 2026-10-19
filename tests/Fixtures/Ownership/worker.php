<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Tests\Fixtures\Ownership\WorkerProvider;
use Nvl\Data\Providers\DataServiceProvider;
use Nvl\Ownership\Providers\OwnershipServiceProvider;
use Nvl\Support\Providers\LocaleServiceProvider;
use Nvl\Support\Providers\SupportServiceProvider;
use Orchestra\Testbench\Foundation\Application as TestbenchApplication;
use Spatie\LaravelData\LaravelDataServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

require dirname(__DIR__, 6).'/vendor/autoload.php';
$source = json_decode($argv[1], true, flags: JSON_THROW_ON_ERROR);
if (! is_array($source) || ($source['driver'] ?? null) !== 'pgsql' || ! is_string($source['database'] ?? null)
    || preg_match('/^nvl_own_test_[a-z0-9_]+$/D', $source['database']) !== 1) {
    throw new RuntimeException('Auth workers require an explicitly dedicated PostgreSQL source.');
}
WorkerProvider::useSource($source);
$application = TestbenchApplication::create(options: ['load_environment_variables' => false, 'extra' => ['dont-discover' => ['*'], 'providers' => [SupportServiceProvider::class, OwnershipServiceProvider::class, LocaleServiceProvider::class, PermissionServiceProvider::class, SanctumServiceProvider::class, LaravelDataServiceProvider::class, DataServiceProvider::class, AuthServiceProvider::class, WorkerProvider::class]]]);
$kernel = $application->make(Kernel::class);
$status = $kernel->call('queue:work', ['connection' => 'database', '--stop-when-empty' => true, '--sleep' => 0, '--tries' => 1, '--timeout' => 10, '--force' => true, '--no-interaction' => true]);
if ($status !== 0) {
    fwrite(STDERR, $kernel->output());
    exit($status);
}
fwrite(STDOUT, 'auth-worker-complete');
