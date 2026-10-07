<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Contracts\Auth\Access\Gate;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Support\Providers\LocaleServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/** Boots explicitly adopted permission storage before its first migration. */
abstract class FreshAdoptedAuthProviderTestCase extends DisabledAuthProviderTestCase
{
    /**
     * Match archive discovery, where Auth boots before Spatie Permission.
     *
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LocaleServiceProvider::class, AuthServiceProvider::class, PermissionServiceProvider::class, SanctumServiceProvider::class];
    }

    /** Configure fresh adopted storage and an eagerly resolved host Gate. */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('nvl-auth.enabled', true);
        $app['config']->set('nvl-auth.migrations.enabled', false);
        $app['config']->set('nvl-auth.adoption.spatie_storage.enabled', true);
        $app->make(Gate::class);
        $app->make('db')->connection()->enableQueryLog();
    }
}
