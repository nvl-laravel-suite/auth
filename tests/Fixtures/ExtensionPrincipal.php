<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Laravel\Sanctum\HasApiTokens;
use Nvl\Auth\Models\User;
use Spatie\Permission\Traits\HasRoles;

/** Example host model; its custom attributes remain explicitly fillable. */
final class ExtensionPrincipal extends User
{
    use HasApiTokens;
    use HasRoles;

    /** @var list<string> */
    protected $fillable = ['job_title', 'phone'];
}
