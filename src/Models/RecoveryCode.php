<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\RecoveryCodeFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;

/**
 * Stores one independently consumable hashed recovery code.
 *
 * @property string $batch_id
 * @property string $subject_type
 * @property string $subject_id
 * @property string $code_hash
 * @property CarbonImmutable|null $used_at
 * @property CarbonImmutable|null $revoked_at
 */
#[UseFactory(RecoveryCodeFactory::class)]
final class RecoveryCode extends AuthModel
{
    public const TABLE = AuthTables::RecoveryCodes;

    /** @use HasFactory<RecoveryCodeFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'batch_id',
        'subject_type',
        'subject_id',
        'code_hash',
        'used_at',
        'revoked_at',
    ];

    /** @var list<string> */
    protected $hidden = ['code_hash'];

    /**
     * Define recovery-code casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'used_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }
}
