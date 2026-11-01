<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\RememberCredentialFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Support\AuthInstantCast;

/** Per-device, one-use remember credential; no plaintext secret or cookie is retained.
 * @property string $selector
 * @property string $secret_hash
 * @property string $subject_type
 * @property string $subject_id
 * @property string $guard_name
 * @property string $provider_hash
 * @property string $session_family_id
 * @property int $security_revision
 * @property CarbonImmutable $absolute_expires_at
 * @property CarbonImmutable|null $consumed_at
 * @property CarbonImmutable|null $revoked_at
 * @property string|null $rotated_to_id
 *
 * @api
 */
final class RememberCredential extends AuthModel
{
    /** @use HasFactory<RememberCredentialFactory> */
    use HasFactory;

    protected static function newFactory(): RememberCredentialFactory
    {
        return RememberCredentialFactory::new();
    }

    public const TABLE = AuthTables::RememberCredentials;

    protected $table = self::TABLE;

    protected $fillable = ['selector', 'secret_hash', 'subject_type', 'subject_id', 'guard_name', 'provider_hash', 'session_family_id', 'security_revision', 'absolute_expires_at', 'consumed_at', 'revoked_at', 'rotated_to_id'];

    protected $hidden = ['selector', 'secret_hash', 'provider_hash', 'session_family_id', 'rotated_to_id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['security_revision' => 'integer', 'absolute_expires_at' => AuthInstantCast::class, 'consumed_at' => AuthInstantCast::class, 'revoked_at' => AuthInstantCast::class];
    }
}
