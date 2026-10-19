<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Nvl\Support\Ownership\Contracts\Ownable;
use Nvl\Support\Ownership\Traits\HasOwnership;
use Nvl\Support\Ownership\ValueObjects\OwnershipDefinition;

/**
 * Retains one durable serialization row for an owner's complete membership lifetime.
 *
 * @internal
 *
 * @property string|null $owner_scope_key
 * @property string|null $owner_reference
 */
final class OwnerMembershipLock extends AuthModel implements Ownable
{
    use HasOwnership;

    protected $table = 'nvl_auth_owner_membership_locks';

    protected $guarded = ['*'];

    /** Keep the lock bound to one permanent canonical owner. */
    public static function ownershipDefinition(): OwnershipDefinition
    {
        return OwnershipDefinition::captured();
    }
}
