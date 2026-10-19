<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Data\Providers\DataServiceProvider;
use Nvl\Ownership\Tests\OwnershipTestCase;
use Nvl\Support\Providers\LocaleServiceProvider;
use Spatie\LaravelData\LaravelDataServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/** Combines global Auth with an independently selected Ownership runtime. */
abstract class GlobalAuthOwnerScopeTestCase extends OwnershipTestCase
{
    protected function getPackageProviders($app): array
    {
        return [...parent::getPackageProviders($app), LocaleServiceProvider::class, PermissionServiceProvider::class, SanctumServiceProvider::class, LaravelDataServiceProvider::class, DataServiceProvider::class, AuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set(['nvl-auth.ownership.scoped' => false, 'nvl-auth.migrations.enabled' => false]);
    }
}
