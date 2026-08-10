<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;

/** Domain profile fixture used to prove relation-safe principal mapping. */
final class MappedPrincipalProfile extends Model
{
    /** @var string */
    protected $table = 'mapped_principal_profiles';

    /** @var list<string> */
    protected $fillable = ['user_id', 'label'];
}
