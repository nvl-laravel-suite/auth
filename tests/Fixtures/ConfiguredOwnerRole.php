<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Models\Role;

/** Extends the native role while retaining the package's guarded ownership capability. */
final class ConfiguredOwnerRole extends Role {}
