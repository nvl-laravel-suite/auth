<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\ImpersonationFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Support\AuthInstantCast;

/** Durable grant bound to the original admitted browser, never a standalone bearer.
 * @property string $actor_type
 * @property string $actor_id
 * @property string $effective_subject_type
 * @property string $effective_subject_id
 * @property string $browser_session_id
 * @property string $guard_name
 * @property int $actor_revision
 * @property int $target_revision
 * @property string $reason
 * @property array<string, mixed>|null $owner_reference
 * @property string|null $active_session_key
 * @property CarbonImmutable $started_at
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $stopped_at
 * @property string|null $stop_reason
 *
 * @api
 */
final class Impersonation extends AuthModel
{
    /** @use HasFactory<ImpersonationFactory> */
    use HasFactory;

    protected static function newFactory(): ImpersonationFactory
    {
        return ImpersonationFactory::new();
    }

    public const TABLE = AuthTables::Impersonations;

    protected $table = self::TABLE;

    protected $fillable = ['actor_type', 'actor_id', 'effective_subject_type', 'effective_subject_id', 'browser_session_id', 'guard_name', 'actor_revision', 'target_revision', 'reason', 'owner_reference', 'active_session_key', 'started_at', 'expires_at', 'stopped_at', 'stop_reason'];

    protected $hidden = ['reason', 'owner_reference', 'active_session_key'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['actor_revision' => 'integer', 'target_revision' => 'integer', 'reason' => 'encrypted', 'owner_reference' => 'encrypted:array', 'started_at' => AuthInstantCast::class, 'expires_at' => AuthInstantCast::class, 'stopped_at' => AuthInstantCast::class];
    }
}
