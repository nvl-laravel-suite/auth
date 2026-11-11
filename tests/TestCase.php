<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Arr;

/** Transaction-wrapped isolation for ordinary persisted domain operations. */
abstract class TestCase extends AuthTestCase
{
    use RefreshDatabase;

    /** Package and connection configuration the shared test schema was last migrated with; migrations and table charsets depend on it. */
    protected static ?string $migratedConfiguration = null;

    /** Rebuild instead of reusing a schema that another test migrated with different configuration. */
    protected function beforeRefreshingDatabase(): void
    {
        if (self::$migratedConfiguration !== $this->migrationConfiguration()) {
            RefreshDatabaseState::$migrated = false;
        }
    }

    protected function afterRefreshingDatabase(): void
    {
        self::$migratedConfiguration = $this->migrationConfiguration();
    }

    protected function migrationConfiguration(): string
    {
        $config = $this->app->make('config');

        return md5(serialize([
            Arr::only($config->all(), ['auth', 'nvl-auth', 'nvl-core', 'nvl-ownership', 'permission']),
            $config->get('database.connections.'.$config->get('database.default')),
        ]));
    }
}
