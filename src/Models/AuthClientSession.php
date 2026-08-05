<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Nvl\Auth\Database\Factories\AuthClientSessionFactory;

/**
 * Correlates a host Laravel session with one Auth client without replacing it.
 *
 * @property string $client_id
 * @property string|null $subject_type
 * @property string|null $subject_id
 * @property string $session_id_hash
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property array<string, mixed>|null $metadata
 * @property CarbonImmutable|null $authenticated_at
 * @property CarbonImmutable $last_seen_at
 * @property CarbonImmutable|null $ended_at
 * @property string|null $end_reason
 */
#[UseFactory(AuthClientSessionFactory::class)]
final class AuthClientSession extends AuthModel
{
    public const TABLE = 'nvl_auth_client_sessions';

    /** @use HasFactory<AuthClientSessionFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'client_id',
        'subject_type',
        'subject_id',
        'session_id_hash',
        'ip_address',
        'user_agent',
        'metadata',
        'authenticated_at',
        'last_seen_at',
        'ended_at',
        'end_reason',
    ];

    /** @var list<string> */
    protected $hidden = ['session_id_hash', 'ip_address', 'user_agent'];

    /**
     * Define client-session casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'ip_address' => 'encrypted',
            'user_agent' => 'encrypted',
            'metadata' => 'encrypted:array',
            'authenticated_at' => 'immutable_datetime',
            'last_seen_at' => 'immutable_datetime',
            'ended_at' => 'immutable_datetime',
        ];
    }

    /**
     * Get the owning client.
     *
     * @return BelongsTo<AuthClient, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(AuthClient::class, 'client_id');
    }
}
