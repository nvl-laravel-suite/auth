<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Nvl\Auth\Database\Factories\AuthClientFactory;

/**
 * Represents one package-managed first-party authentication client.
 *
 * @property string $name
 * @property string $surface
 * @property string $base_url
 * @property list<string>|null $return_paths
 * @property list<string>|null $allowed_origins
 * @property list<string>|null $allowed_flows
 * @property array<string, mixed>|null $metadata
 * @property bool $is_active
 * @property CarbonImmutable|null $last_used_at
 */
#[UseFactory(AuthClientFactory::class)]
final class AuthClient extends AuthModel
{
    public const TABLE = 'nvl_auth_clients';

    /** @use HasFactory<AuthClientFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'name',
        'surface',
        'base_url',
        'return_paths',
        'allowed_origins',
        'allowed_flows',
        'metadata',
        'is_active',
        'last_used_at',
    ];

    /**
     * Define client attribute casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'return_paths' => 'array',
            'allowed_origins' => 'array',
            'allowed_flows' => 'array',
            'metadata' => 'array',
            'is_active' => 'boolean',
            'last_used_at' => 'immutable_datetime',
        ];
    }

    /**
     * Get the client-owned session correlation records.
     *
     * @return HasMany<AuthClientSession, $this>
     */
    public function sessions(): HasMany
    {
        return $this->hasMany(AuthClientSession::class, 'client_id');
    }
}
