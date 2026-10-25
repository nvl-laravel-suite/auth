<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Contracts\OwnerAvailability;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

/** Configures native host policy in both producer and real worker processes. */
final class AuthDeliveryWorkerProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->make('config')->set([
            'nvl-core.owners' => [Company::class, Actor::class],
            'nvl-ownership.enabled' => true,
            'nvl-ownership.migrations.enabled' => false,
            'queue.default' => 'database',
            'queue.connections.database.connection' => 'sqlite',
            'queue.connections.database.retry_after' => 1,
            'queue.failed' => ['driver' => 'database-uuids', 'database' => 'sqlite', 'table' => 'failed_jobs'],
        ]);
        $this->app->bind(OwnerAccess::class, static fn () => new class implements OwnerAccess
        {
            public function assertCanEnter(Authenticatable $actor, Model $owner): void
            {
                if (! $actor instanceof Actor || $actor->getAuthIdentifier() !== 1 || ! $owner instanceof Company) {
                    throw new OwnershipViolation;
                }
            }
        });
        $this->app->bind(OwnerAvailability::class, static fn () => new class implements OwnerAvailability
        {
            public function assertAvailable(Model $owner): void
            {
                if (! $owner->exists || $owner->getAttribute('active') !== true) {
                    throw new OwnershipViolation;
                }
            }
        });
    }

    public function boot(): void
    {
        Event::listen(AuthDeliveryRequested::class, RecordQueuedAuthDelivery::class.'@handle');
        Event::listen(AuthDeliveryRequested::class, ThrowingQueuedAuthDelivery::class.'@handle');
        $recordScope = static function (): void {
            DB::table('nvl_auth_test_worker_scopes')->insert(['mode' => app(OwnershipContext::class)->snapshot()->mode->value]);
        };
        Queue::looping($recordScope);
        $this->app->terminating($recordScope);
    }
}
