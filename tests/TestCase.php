<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;

/** Transaction-wrapped isolation for ordinary persisted domain operations. */
abstract class TestCase extends AuthTestCase
{
    use RefreshDatabase;
}
