<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Models\OwnerMembership;

/** Native consumer extension with its own additive membership table. */
final class ConfiguredOwnerMembership extends OwnerMembership
{
    protected $table = 'host_owner_memberships';
}
