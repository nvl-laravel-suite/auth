<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

/** Real commits for browser transitions; no outer testing transaction. */
abstract class StatefulAuthTestCase extends TestCase
{
    use CommitsTestDatabase;
}
