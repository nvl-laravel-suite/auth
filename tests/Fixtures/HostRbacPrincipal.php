<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Spatie\Permission\Traits\HasRoles;

/**
 * Represents a host-owned principal schema that adopts only package RBAC.
 *
 * @property string $id
 * @property string $name
 * @property string $email
 */
final class HostRbacPrincipal extends Authenticatable
{
    use HasRoles;
    use HasUuids;

    /** @var string */
    protected $table = 'nvl_auth_users';

    /** @var string */
    protected $keyType = 'string';

    /** @var string */
    protected $guard_name = 'web';

    /** @var list<string> */
    protected $fillable = ['name', 'email', 'password'];
}
