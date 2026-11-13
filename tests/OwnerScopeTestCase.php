<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Closure;
use Illuminate\Contracts\Foundation\MaintenanceMode;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;
use Nvl\Auth\Tests\Fixtures\AllowAllSystemMutationAccess;
use Nvl\Auth\Tests\Fixtures\AuthTestMaintenanceMode;
use Nvl\Auth\Tests\Fixtures\TestUser as User;
use Nvl\Ownership\Contracts\OwnershipAdoptionAccess;
use Nvl\Ownership\Services\OwnershipAdoptionCoordinator;
use Nvl\Ownership\Tests\OwnershipTestCase;
use Nvl\Ownership\ValueObjects\OwnershipAdoptionPlan;
use Nvl\Ownership\ValueObjects\OwnershipMapping;
use Nvl\Ownership\ValueObjects\OwnershipOperation;
use Nvl\Support\Providers\LocaleServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/** Runs native Auth ownership without the Tenancy provider or outer database transactions. */
abstract class OwnerScopeTestCase extends OwnershipTestCase
{
    public OwnershipAdoptionPlan $adoptionPlan;

    /** @var array<string, class-string<Model>> */
    private array $originalMorphMap = [];

    protected function tearDown(): void
    {
        try {
            parent::tearDown();
        } finally {
            Relation::morphMap($this->originalMorphMap, false);
        }
    }

    protected function getPackageProviders($app): array
    {
        return [...parent::getPackageProviders($app), LocaleServiceProvider::class, PermissionServiceProvider::class, SanctumServiceProvider::class, AuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set([
            'app.key' => 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
            'hashing.bcrypt.rounds' => 4,
            'auth.timebox_duration' => 0,
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
            'auth.passwords.users.table' => 'nvl_auth_password_reset_tokens',
            'nvl-ownership.system_operations' => ['auth-membership-bootstrap'],
        ]);
    }

    protected function setUp(): void
    {
        $this->originalMorphMap = Relation::morphMap();
        if (in_array('sqlite-trigger-removal', $this->groups(), true)
            && getenv('NVL_OWNERSHIP_TEST_DRIVER') === 'pgsql') {
            $this->markTestSkipped('SQLite trigger-removal path; native writes and race tests cover PostgreSQL.');
        }
        parent::setUp();
        if (! $this->hasRetainedOwnershipSchema()) {
            foreach (glob(__DIR__.'/../database/migrations/*.php') ?: [] as $path) {
                (require $path)->up();
            }
            (require __DIR__.'/../../ownership/database/migrations/ownership/2026_10_18_000001_nvl_ownership_create_adoption_tables.php')->up();
        }
        $this->app->bind(AuthManagementAccess::class, AllowAllManagementAccess::class);
        $this->app->bind(SystemMutationAccess::class, AllowAllSystemMutationAccess::class);
        $this->app->bind(OwnershipAdoptionAccess::class, static fn () => new class implements OwnershipAdoptionAccess
        {
            public function authorize(OwnershipOperation $operation): void {}
        });
        $this->app->instance(MaintenanceMode::class, new AuthTestMaintenanceMode);
        $this->app->make(MaintenanceMode::class)->activate([]);
        if (! $this->hasRetainedOwnershipSchema()) {
            $this->adoptSchema();
        }
        $this->app->make(MaintenanceMode::class)->deactivate();
        $this->allowOwners();
    }

    private function adoptSchema(): void
    {
        $coordinator = $this->app->make(OwnershipAdoptionCoordinator::class);
        $operation = new OwnershipOperation('auth-adopt', 'operator', '1');
        $plan = $coordinator->prepare(['auth'], $this->adoptionMappings(), $operation);
        $this->adoptionPlan = $plan;
        while (! $coordinator->backfill($plan, 100, $operation)) {
        }
        $coordinator->activate($plan, $operation);
    }

    /** Supply reviewed legacy records before the first native preparation.
     * @return list<OwnershipMapping>
     */
    protected function adoptionMappings(): array
    {
        return [];
    }

    /** @param array<string, mixed> $overrides */
    protected function withFixtureConfiguration(array $overrides, Closure $assertion): void
    {
        $configuration = $this->app->make('config');
        $original = $configuration->getMany(array_keys($overrides));
        $configuration->set($overrides);
        try {
            $assertion();
        } finally {
            $configuration->set($original);
        }
    }
}
