<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;

/**
 * Stores one short-lived, one-use tenant authentication binding.
 *
 * @property string $tenant_id
 * @property TenantAuthenticationPurpose $purpose
 * @property string $nonce_hash
 * @property string $session_binding_hash
 * @property string|null $subject_type
 * @property string|null $subject_id
 * @property array<string, mixed>|null $payload
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $consumed_at
 */
final class TenantAuthenticationIntent extends AuthModel
{
    public const string TABLE = AuthTables::TenantAuthenticationIntents;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'tenant_id', 'purpose', 'nonce_hash', 'session_binding_hash', 'subject_type', 'subject_id',
        'payload', 'expires_at', 'consumed_at',
    ];

    /** @var list<string> */
    protected $hidden = ['nonce_hash', 'session_binding_hash', 'payload'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'purpose' => TenantAuthenticationPurpose::class,
            'payload' => 'encrypted:array',
            'expires_at' => 'immutable_datetime',
            'consumed_at' => 'immutable_datetime',
        ];
    }
}
