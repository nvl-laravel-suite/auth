<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Ownership;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\ServiceProvider;
use Nvl\Auth\Models\User;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Contracts\OwnerAvailability;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

/** Boots the same Auth model graph and fresh membership admission in an independent worker. */
final class WorkerProvider extends ServiceProvider
{
    /** @var array<string, mixed> */
    private static array $source = [];

    /** @param array<string, mixed> $source */
    public static function useSource(array $source): void
    {
        self::$source = $source;
    }

    /** Configure actual isolated storage without running migrations or manufacturing readiness. */
    public function register(): void
    {
        $this->app->make('config')->set([
            'app.key' => 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
            'database.default' => 'sqlite',
            'database.connections.sqlite' => self::$source,
            'nvl-core.owners' => [Company::class, Actor::class],
            'nvl-ownership.enabled' => true,
            'nvl-ownership.migrations.enabled' => false,
            'nvl-tenancy.enabled' => false,
            'nvl-auth.ownership.scoped' => true,
            'nvl-auth.adoption.spatie_storage.enabled' => true,
            'nvl-auth.adoption.principal_model' => ['enabled' => true, 'guard' => 'web', 'provider' => 'users'],
            'nvl-auth.migrations.enabled' => false,
            'nvl-auth.migrations.install_all' => true,
            'nvl-auth.features.memberships.enabled' => true,
            'nvl-auth.features.rbac.enabled' => true,
            'nvl-auth.features.invitations.enabled' => true,
            'nvl-auth.features.api_tokens.enabled' => true,
            'nvl-auth.features.api_tokens.settings.abilities' => ['profile:read'],
            'nvl-auth.features.rbac.models.principal' => User::class,
            'nvl-auth.features.principal_management.models.user' => User::class,
            'auth.providers.users.model' => User::class,
            'nvl-ownership.system_operations' => ['auth-membership-bootstrap'],
            'queue.default' => 'database',
            'queue.connections.database.connection' => 'sqlite',
            'queue.failed' => ['driver' => 'database-uuids', 'database' => 'sqlite', 'table' => 'failed_jobs'],
            'cache.default' => 'array',
        ]);
        $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
        $this->app->bind(OwnerAvailability::class, static fn (): OwnerAvailability => new class implements OwnerAvailability
        {
            public function assertAvailable(Model $owner): void
            {
                if (! $owner instanceof Company || $owner->getAttribute('active') !== true) {
                    throw new OwnershipViolation;
                }
            }
        });
    }

    /** Observe scope restoration after each independent worker execution. */
    public function boot(): void
    {
        $this->app->make('events')->listen(JobProcessed::class, static function (): void {
            DB::table('ownership_queue_probes')->insert(['stage' => 'auth-worker-after', 'owner' => app(OwnershipContext::class)->snapshot()->mode->value, 'label' => 'worker']);
        });
    }
}
