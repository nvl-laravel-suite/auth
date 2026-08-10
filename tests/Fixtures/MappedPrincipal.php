<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Database\Eloquent\Relations\HasOne;
use Nvl\Auth\Models\User;

/** Host principal fixture whose domain profile relation must remain usable. */
final class MappedPrincipal extends User
{
    /** @return HasOne<MappedPrincipalProfile, $this> */
    public function profile(): HasOne
    {
        return $this->hasOne(MappedPrincipalProfile::class, 'user_id');
    }
}
