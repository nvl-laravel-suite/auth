<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\PrincipalSecurityStateFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;

/** Central monotonic security epoch; retained through principal soft deletion.
 * @property string $subject_type
 * @property string $subject_id
 * @property int $revision
 *
 * @internal
 */
#[UseFactory(PrincipalSecurityStateFactory::class)]
final class PrincipalSecurityState extends AuthModel
{
    public const TABLE = AuthTables::PrincipalSecurityStates;

    /** @use HasFactory<PrincipalSecurityStateFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = ['subject_type', 'subject_id', 'revision'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['revision' => 'integer'];
    }

    /** Resolve the package fixture factory. */
    protected static function newFactory(): PrincipalSecurityStateFactory
    {
        return PrincipalSecurityStateFactory::new();
    }
}
