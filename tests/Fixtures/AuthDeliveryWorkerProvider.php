<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Enums\TenantStatus;
use Nvl\Tenancy\Tests\Fixtures\ArrayTenantDirectory;
use Nvl\Tenancy\ValueObjects\TenantDescriptor;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Configures the isolated real-worker Auth delivery proof. */
final class AuthDeliveryWorkerProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->make(Repository::class)->set([
            'tenancy.enabled' => true,
            'tenancy.directory.driver' => 'host',
            'queue.default' => 'database',
            'queue.connections.database.connection' => 'sqlite',
            'queue.connections.database.retry_after' => 1,
            'queue.failed.driver' => 'database-uuids',
            'queue.failed.database' => 'sqlite',
            'queue.failed.table' => 'failed_jobs',
        ]);
        $tenants = [];
        foreach ([AuthTenancyScenario::A, AuthTenancyScenario::B] as $value) {
            $id = new TenantId($value);
            $tenants[$value] = new TenantDescriptor($id, TenantStatus::Active);
        }
        $this->app->instance(TenantDirectory::class, new ArrayTenantDirectory($tenants));
    }

    public function boot(): void
    {
        Event::listen(AuthDeliveryRequested::class, RecordQueuedAuthDelivery::class.'@handle');
        Event::listen(AuthDeliveryRequested::class, ThrowingQueuedAuthDelivery::class.'@handle');
        Queue::looping(static function (): void {
            DB::table('nvl_auth_test_worker_scopes')->insert([
                'mode' => app(TenantContext::class)->snapshot()->mode->value,
            ]);
        });
        $this->app->terminating(static function (): void {
            DB::table('nvl_auth_test_worker_scopes')->insert([
                'mode' => app(TenantContext::class)->snapshot()->mode->value,
            ]);
        });
    }
}
