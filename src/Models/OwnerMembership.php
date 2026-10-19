<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\OwnerMembershipFactory;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Support\Ownership\Contracts\Ownable;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Traits\HasOwnership;
use Nvl\Support\Ownership\ValueObjects\OwnershipDefinition;

/** One principal's optional membership in a canonical native owner.
 * @property string $subject_type
 * @property string $subject_id
 * @property MembershipStatus $status
 * @property bool $is_owner
 * @property int $revision
 *
 * @api
 *
 * @property string|null $owner_scope_key
 * @property string|null $owner_reference
 */
class OwnerMembership extends Membership implements Ownable
{
    /** @use HasFactory<OwnerMembershipFactory> */
    use HasFactory;

    use HasOwnership;

    protected $table = 'nvl_auth_owner_memberships';

    protected $fillable = ['subject_type', 'subject_id', 'status', 'is_owner', 'revision'];

    protected $attributes = ['status' => 'active', 'is_owner' => false, 'revision' => 1];

    /** Resolve native storage independently of the compatibility base table. */
    public function getTable(): string
    {
        return $this->table ?? throw new OwnershipConfigurationInvalid('Owner membership storage requires an explicit table.');
    }

    /** Preserve the fixed operational ownership declaration. */
    final public static function ownershipDefinition(): OwnershipDefinition
    {
        return OwnershipDefinition::captured();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['status' => MembershipStatus::class, 'is_owner' => 'boolean', 'revision' => 'integer'];
    }

    /** Return the ownership-native fixture factory.
     * @internal
     */
    protected static function newFactory(): OwnerMembershipFactory
    {
        return OwnerMembershipFactory::new();
    }
}
