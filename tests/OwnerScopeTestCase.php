<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Contracts\Foundation\MaintenanceMode;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Models\User;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;
use Nvl\Auth\Tests\Fixtures\AllowAllSystemMutationAccess;
use Nvl\Auth\Tests\Fixtures\AuthTestMaintenanceMode;
use Nvl\Data\Providers\DataServiceProvider;
use Nvl\Ownership\Contracts\OwnershipAdoptionAccess;
use Nvl\Ownership\Services\OwnershipAdoptionCoordinator;
use Nvl\Ownership\Tests\OwnershipTestCase;
use Nvl\Ownership\ValueObjects\OwnershipAdoptionPlan;
use Nvl\Ownership\ValueObjects\OwnershipMapping;
use Nvl\Ownership\ValueObjects\OwnershipOperation;
use Nvl\Support\Providers\LocaleServiceProvider;
use Spatie\LaravelData\LaravelDataServiceProvider;
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
        return [...parent::getPackageProviders($app), LocaleServiceProvider::class, PermissionServiceProvider::class, SanctumServiceProvider::class, LaravelDataServiceProvider::class, DataServiceProvider::class, AuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set([
            'app.key' => 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
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
        ]);
    }

    protected function setUp(): void
    {
        $this->originalMorphMap = Relation::morphMap();
        parent::setUp();
        foreach (glob(__DIR__.'/../database/migrations/*.php') ?: [] as $path) {
            (require $path)->up();
        }
        (require __DIR__.'/../../ownership/database/migrations/ownership/2026_10_18_000001_nvl_ownership_create_adoption_tables.php')->up();
        $this->app->bind(AuthManagementAccess::class, AllowAllManagementAccess::class);
        $this->app->bind(SystemMutationAccess::class, AllowAllSystemMutationAccess::class);
        $this->app->bind(OwnershipAdoptionAccess::class, static fn () => new class implements OwnershipAdoptionAccess
        {
            public function authorize(OwnershipOperation $operation): void {}
        });
        $this->app->instance(MaintenanceMode::class, new AuthTestMaintenanceMode);
        $this->app->make(MaintenanceMode::class)->activate([]);
        $coordinator = $this->app->make(OwnershipAdoptionCoordinator::class);
        $operation = new OwnershipOperation('auth-adopt', 'operator', '1');
        $plan = $coordinator->prepare(['auth'], $this->adoptionMappings(), $operation);
        $this->adoptionPlan = $plan;
        while (! $coordinator->backfill($plan, 100, $operation)) {
        }
        $coordinator->activate($plan, $operation);
        $this->app->make(MaintenanceMode::class)->deactivate();
        $this->allowOwners();
    }

    /** Supply reviewed legacy records before the first native preparation.
     * @return list<OwnershipMapping>
     */
    protected function adoptionMappings(): array
    {
        return [];
    }
}
