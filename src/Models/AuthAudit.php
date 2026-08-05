<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Nvl\Auth\Database\Factories\AuthAuditFactory;

/**
 * Stores one simple, queryable Auth audit fact and bounded metadata.
 *
 * @property string $action
 * @property string $outcome
 * @property string|null $subject_type
 * @property string|null $subject_id
 * @property string|null $actor_type
 * @property string|null $actor_id
 * @property string|null $client_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $request_id
 * @property array<string, mixed>|null $metadata
 */
#[UseFactory(AuthAuditFactory::class)]
final class AuthAudit extends AuthModel
{
    public const TABLE = 'nvl_auth_audits';

    /** @use HasFactory<AuthAuditFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'action',
        'outcome',
        'subject_type',
        'subject_id',
        'actor_type',
        'actor_id',
        'client_id',
        'ip_address',
        'user_agent',
        'request_id',
        'metadata',
    ];

    /** @var list<string> */
    protected $hidden = ['ip_address', 'user_agent', 'metadata'];

    /**
     * Define audit casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'ip_address' => 'encrypted',
            'user_agent' => 'encrypted',
            'metadata' => 'encrypted:array',
        ];
    }

    /**
     * Get the optional first-party client associated with this audit.
     *
     * @return BelongsTo<AuthClient, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(AuthClient::class, 'client_id');
    }
}
