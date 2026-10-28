<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\PendingEmailChangeFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;

/** One-use replacement mailbox proof, separate from the principal's live identity.
 * @property string $subject_type
 * @property string $subject_id
 * @property string $new_email
 * @property string $email_hash
 * @property string $token_hash
 * @property int $security_revision
 * @property string|null $active_key
 * @property array<string, mixed> $context
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $consumed_at
 * @property CarbonImmutable|null $revoked_at
 *
 * @api
 */
final class PendingEmailChange extends AuthModel
{
    /** @use HasFactory<PendingEmailChangeFactory> */
    use HasFactory;

    protected static function newFactory(): PendingEmailChangeFactory
    {
        return PendingEmailChangeFactory::new();
    }

    public const TABLE = AuthTables::PendingEmailChanges;

    protected $table = self::TABLE;

    protected $fillable = ['subject_type', 'subject_id', 'new_email', 'email_hash', 'token_hash', 'security_revision', 'active_key', 'context', 'expires_at', 'consumed_at', 'revoked_at'];

    protected $hidden = ['new_email', 'email_hash', 'token_hash', 'active_key', 'context'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['new_email' => 'encrypted', 'context' => 'encrypted:array', 'security_revision' => 'integer', 'expires_at' => 'immutable_datetime', 'consumed_at' => 'immutable_datetime', 'revoked_at' => 'immutable_datetime'];
    }
}
