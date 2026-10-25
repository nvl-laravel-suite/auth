<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Laravel\Sanctum\HasApiTokens;
use Nvl\Auth\Models\User;
use Spatie\Permission\Traits\HasRoles;

/**
 * Provides one conventional host authenticatable for package integration tests.
 */
final class TestUser extends User implements \Laravel\Sanctum\Contracts\HasApiTokens
{
    use HasApiTokens;
    use HasRoles;
}
