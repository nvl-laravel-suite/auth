<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Models\User;

/** Extends the global credential principal independently of owned membership storage. */
final class ConfiguredOwnerUser extends User {}
