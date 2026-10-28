<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\DatabaseMigrations;

/** Real commits for browser transitions; no outer testing transaction. */
abstract class StatefulAuthTestCase extends AuthTestCase
{
    use DatabaseMigrations;
}
