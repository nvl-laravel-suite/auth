<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\BrowserSessionFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;

/** Authoritative browser binding; never stores the Laravel payload-store identifier.
 * @property string $subject_type
 * @property string $subject_id
 * @property string $guard_name
 * @property string $provider_hash
 * @property string $binding_hash
 * @property int $security_revision
 * @property string $session_family_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string $method
 * @property array<string, mixed> $assurance
 * @property CarbonImmutable $authenticated_at
 * @property CarbonImmutable $last_seen_at
 * @property CarbonImmutable $absolute_expires_at
 * @property CarbonImmutable|null $revoked_at
 *
 * @api
 */
final class BrowserSession extends AuthModel
{
    /** @use HasFactory<BrowserSessionFactory> */
    use HasFactory;

    protected static function newFactory(): BrowserSessionFactory
    {
        return BrowserSessionFactory::new();
    }

    public const TABLE = AuthTables::BrowserSessions;

    protected $table = self::TABLE;

    protected $fillable = ['subject_type', 'subject_id', 'guard_name', 'provider_hash', 'binding_hash', 'security_revision', 'session_family_id', 'method', 'assurance', 'authenticated_at', 'last_seen_at', 'absolute_expires_at', 'revoked_at', 'ip_address', 'user_agent'];

    protected $hidden = ['binding_hash', 'provider_hash', 'assurance', 'session_family_id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['security_revision' => 'integer', 'assurance' => 'encrypted:array', 'ip_address' => 'encrypted', 'user_agent' => 'encrypted', 'authenticated_at' => 'immutable_datetime', 'last_seen_at' => 'immutable_datetime', 'absolute_expires_at' => 'immutable_datetime', 'revoked_at' => 'immutable_datetime'];
    }

    /** Pure snapshot check; admission owns canonical locking and source checks. */
    public function isCurrent(int $revision): bool
    {
        return $this->revoked_at === null && $this->absolute_expires_at->isFuture() && $this->security_revision === $revision;
    }
}
