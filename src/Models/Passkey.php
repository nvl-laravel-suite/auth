<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\PasskeyFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;

/**
 * Stores verified WebAuthn credential material for a host subject.
 *
 * @property string $subject_type
 * @property string $subject_id
 * @property string|null $name
 * @property string $credential_id
 * @property string $credential_id_hash
 * @property string $public_key
 * @property string $user_handle
 * @property int $signature_counter
 * @property list<string>|null $transports
 * @property bool $backup_eligible
 * @property bool $backed_up
 * @property CarbonImmutable|null $last_used_at
 * @property CarbonImmutable|null $revoked_at
 */
#[UseFactory(PasskeyFactory::class)]
final class Passkey extends AuthModel
{
    public const TABLE = AuthTables::Passkeys;

    /** @use HasFactory<PasskeyFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'subject_type',
        'subject_id',
        'name',
        'credential_id',
        'credential_id_hash',
        'public_key',
        'user_handle',
        'signature_counter',
        'transports',
        'backup_eligible',
        'backed_up',
        'last_used_at',
        'revoked_at',
    ];

    /** @var list<string> */
    protected $hidden = ['credential_id', 'credential_id_hash', 'public_key', 'user_handle'];

    /**
     * Define passkey casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'credential_id' => 'encrypted',
            'public_key' => 'encrypted',
            'user_handle' => 'encrypted',
            'signature_counter' => 'integer',
            'transports' => 'array',
            'backup_eligible' => 'boolean',
            'backed_up' => 'boolean',
            'last_used_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }
}
