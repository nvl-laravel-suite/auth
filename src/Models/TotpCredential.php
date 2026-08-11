<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\TotpCredentialFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;

/**
 * Stores one encrypted TOTP secret owned by a host subject.
 *
 * @property string $subject_type
 * @property string $subject_id
 * @property string|null $name
 * @property string $secret
 * @property string $algorithm
 * @property int $digits
 * @property int $period
 * @property int $allowed_drift
 * @property int|null $last_accepted_timestep
 * @property CarbonImmutable|null $confirmed_at
 * @property CarbonImmutable|null $last_used_at
 * @property CarbonImmutable|null $revoked_at
 */
#[UseFactory(TotpCredentialFactory::class)]
final class TotpCredential extends AuthModel
{
    public const TABLE = AuthTables::TotpCredentials;

    /** @use HasFactory<TotpCredentialFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'subject_type',
        'subject_id',
        'name',
        'secret',
        'algorithm',
        'digits',
        'period',
        'allowed_drift',
        'last_accepted_timestep',
        'confirmed_at',
        'last_used_at',
        'revoked_at',
    ];

    /** @var list<string> */
    protected $hidden = ['secret'];

    /**
     * Define TOTP credential casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'digits' => 'integer',
            'period' => 'integer',
            'allowed_drift' => 'integer',
            'last_accepted_timestep' => 'integer',
            'confirmed_at' => 'immutable_datetime',
            'last_used_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }
}
