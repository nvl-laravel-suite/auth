<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

/** Boots enabled Auth services while retaining a complete host integration snapshot. */
abstract class HostAuthAdoptionTestCase extends DisabledAuthProviderTestCase
{
    /** @var array<string, mixed> */
    public array $hostAuth = [];

    /** @var array<string, mixed> */
    public array $hostPermission = [];

    /** Configure host-owned providers, password storage, and permission teams. */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('nvl-auth.enabled', true);
        $app['config']->set('permission.teams', true);
        $app['config']->set('permission.column_names.team_foreign_key', 'host_team_id');
        $this->hostAuth = $app['config']->get('auth');
        $this->hostPermission = $app['config']->get('permission');
    }
}
