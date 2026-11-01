<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Nvl\Auth\Tests\Fixtures\Consumer\RouteServiceProvider;

/** Boots enabled Auth services while retaining a complete host integration snapshot. */
abstract class HostAuthAdoptionTestCase extends DisabledAuthProviderTestCase
{
    use DatabaseMigrations;

    /** Exercise native package adoption without the consumer-owned HTTP fixture. */
    protected function getPackageProviders($app): array
    {
        return array_values(array_filter(parent::getPackageProviders($app),
            static fn (string $provider): bool => $provider !== RouteServiceProvider::class));
    }

    /** @var array<string, mixed> */
    public array $hostAuth = [];

    /** @var array<string, mixed> */
    public array $hostPermission = [];

    /** Configure host-owned providers, password storage, and permission teams. */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('nvl-auth.enabled', true);
        $app['config']->set('nvl-auth.migrations.enabled', false);
        $app['config']->set('permission.teams', true);
        $app['config']->set('permission.column_names.team_foreign_key', 'host_team_id');
        $this->hostAuth = $app['config']->get('auth');
        $this->hostPermission = $app['config']->get('permission');
    }
}
