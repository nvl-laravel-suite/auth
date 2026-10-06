<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Support\Tenancy\Contracts\TenantContext;
use Nvl\Support\Tenancy\Contracts\TenantDirectory;
use Nvl\Support\Tenancy\Enums\TenantStatus;
use Nvl\Support\Tenancy\ValueObjects\TenantDescriptor;
use Nvl\Support\Tenancy\ValueObjects\TenantId;
use Nvl\Tenancy\Tests\Fixtures\ArrayTenantDirectory;

/** Configures the isolated real-worker Auth delivery proof. */
final class AuthDeliveryWorkerProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->make(Repository::class)->set([
            'nvl-tenancy.enabled' => true,
            'nvl-tenancy.directory.driver' => 'host',
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
