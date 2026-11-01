<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Laravel\Sanctum\HasApiTokens;
use Nvl\Auth\Models\User;
use Spatie\Permission\Traits\HasRoles;

/** A supported host principal with calendar and locally formatted extension casts. */
final class CalendarPrincipal extends User
{
    use HasApiTokens;
    use HasRoles;

    /** @var list<string> */
    protected $fillable = ['profile_date', 'profile_immutable_date', 'profile_formatted_date', 'profile_local_time'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [...parent::casts(),
            'profile_date' => 'date',
            'profile_immutable_date' => 'immutable_date',
            'profile_formatted_date' => 'date:Y-m-d',
            'profile_local_time' => 'datetime:Y-m-d H:i',
        ];
    }
}
