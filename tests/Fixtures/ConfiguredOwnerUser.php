<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Laravel\Sanctum\HasApiTokens;
use Nvl\Auth\Models\User;
use Spatie\Permission\Traits\HasRoles;

/** Extends the global credential principal independently of owned membership storage. */
final class ConfiguredOwnerUser extends User
{
    use HasApiTokens;
    use HasRoles;
}
