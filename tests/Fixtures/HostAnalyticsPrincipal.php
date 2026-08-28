<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Spatie\Permission\Traits\HasRoles;

/** Represents a host-owned RBAC principal stored outside the package user table. */
final class HostAnalyticsPrincipal extends Authenticatable
{
    use HasRoles;
    use HasUuids;

    /** @var string */
    protected $table = 'host_analytics_principals';

    /** @var string */
    protected $keyType = 'string';

    /** @var string */
    protected $guard_name = 'web';

    /** @var list<string> */
    protected $fillable = ['name', 'email', 'enabled_for_access'];

    /** Define host principal casts. */
    protected function casts(): array
    {
        return ['enabled_for_access' => 'boolean'];
    }
}
