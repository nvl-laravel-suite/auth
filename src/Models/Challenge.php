<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\ChallengeFactory;

/**
 * Stores one hashed magic-link, verification, or security-code challenge.
 *
 * @property string $type
 * @property string $purpose
 * @property string|null $subject_type
 * @property string|null $subject_id
 * @property string|null $recipient_hash
 * @property string $secret_hash
 * @property string|null $secondary_secret_hash
 * @property string|null $active_key
 * @property array<string, mixed>|null $payload
 * @property int $attempts
 * @property int $max_attempts
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $consumed_at
 * @property CarbonImmutable|null $revoked_at
 */
#[UseFactory(ChallengeFactory::class)]
final class Challenge extends AuthModel
{
    public const TABLE = 'nvl_auth_challenges';

    /** @use HasFactory<ChallengeFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'type',
        'purpose',
        'subject_type',
        'subject_id',
        'recipient_hash',
        'secret_hash',
        'secondary_secret_hash',
        'active_key',
        'payload',
        'attempts',
        'max_attempts',
        'expires_at',
        'consumed_at',
        'revoked_at',
    ];

    /** @var list<string> */
    protected $hidden = ['recipient_hash', 'secret_hash', 'secondary_secret_hash', 'active_key', 'payload'];

    /**
     * Define challenge casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload' => 'encrypted:array',
            'attempts' => 'integer',
            'max_attempts' => 'integer',
            'expires_at' => 'immutable_datetime',
            'consumed_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }

    /**
     * Determine whether this challenge may be attempted.
     */
    public function isUsable(): bool
    {
        return $this->consumed_at === null
            && $this->revoked_at === null
            && $this->attempts < $this->max_attempts
            && $this->expires_at->isFuture();
    }
}
