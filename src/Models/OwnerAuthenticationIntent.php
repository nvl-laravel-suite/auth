<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Nvl\Support\Ownership\Contracts\Ownable;
use Nvl\Support\Ownership\Traits\HasOwnership;
use Nvl\Support\Ownership\ValueObjects\OwnershipDefinition;

/**
 * Stores a one-use owner selection proof separately from global authentication.
 *
 * @internal
 *
 * @property string $purpose
 * @property string $nonce_hash
 * @property string $session_binding_hash
 * @property string|null $subject_type
 * @property string|null $subject_id
 * @property array<string, mixed>|null $payload
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $consumed_at
 * @property string|null $owner_scope_key
 * @property string|null $owner_reference
 */
final class OwnerAuthenticationIntent extends AuthModel implements Ownable
{
    use HasOwnership;

    protected $table = 'nvl_auth_owner_authentication_intents';

    protected $guarded = ['id', 'owner_scope_key', 'owner_reference'];

    protected $hidden = ['nonce_hash', 'session_binding_hash', 'payload'];

    /** Keep one fixed native owner for each selection proof. */
    public static function ownershipDefinition(): OwnershipDefinition
    {
        return OwnershipDefinition::captured();
    }

    /** @return array<string,string> */
    protected function casts(): array
    {
        return ['payload' => 'encrypted:array', 'expires_at' => 'immutable_datetime', 'consumed_at' => 'immutable_datetime'];
    }
}
