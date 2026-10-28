<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Nvl\Auth\Tests\Fixtures\Consumer\RouteServiceProvider;
use Nvl\Support\Providers\SupportServiceProvider;

/** Committed delivery uses the shared host setup without consumer routes. */
abstract class CommittedDeliveryTestCase extends AuthTestCase
{
    use DatabaseMigrations;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [SupportServiceProvider::class, ...array_values(array_filter(parent::getPackageProviders($app), static fn (string $provider): bool => $provider !== RouteServiceProvider::class))];
    }
}
