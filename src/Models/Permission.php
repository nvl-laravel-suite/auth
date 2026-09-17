<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\Grammars\PostgresGrammar;
use Nvl\Auth\Database\Factories\PermissionFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Relations\TextCastColumnComparison;
use Spatie\Permission\Models\Permission as SpatiePermission;

/**
 * Provides the package-owned Spatie Permission permission model.
 *
 * @property string $id
 * @property string $name
 * @property string $guard_name
 * @property string|null $display_name
 * @property string|null $description
 * @property string|null $group
 * @property bool $is_system
 * @property array<string, mixed>|null $metadata
 * @property-read int|null $users_count
 * @property-read int|null $roles_count
 */
#[UseFactory(PermissionFactory::class)]
class Permission extends SpatiePermission
{
    /** @use HasFactory<PermissionFactory> */
    use HasFactory;

    use HasUuids;

    public const TABLE = AuthTables::Permissions;

    /** @var string */
    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = [
        'name',
        'guard_name',
        'display_name',
        'description',
        'group',
        'is_system',
        'metadata',
    ];

    /** @var array<string, mixed> */
    protected $attributes = ['is_system' => false];

    /**
     * Resolve the configured package table.
     */
    public function getTable(): string
    {
        $configured = config('nvl-auth.tables.permissions');

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : self::TABLE;
    }

    /**
     * Resolve the immutable package operational connection.
     */
    public function getConnectionName(): ?string
    {
        $configured = config('nvl-auth.connection');

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : parent::getConnectionName();
    }

    /** Constrain direct inverse assignments to the active team and membership. */
    /** @return BelongsToMany<Model, $this> */
    public function users(): BelongsToMany
    {
        if (config('tenancy.enabled') !== true) {
            return parent::users();
        }
        $tenant = getPermissionsTeamId();
        $relation = parent::users()->wherePivot('tenant_id', $tenant);
        $principal = $relation->getRelated();

        return $relation->whereExists(static function (QueryBuilder $query) use ($principal, $tenant): void {
            $principalKey = $principal->qualifyColumn($principal->getKeyName());
            $query->selectRaw('1')->from(AuthTables::TenantMemberships);
            if ($query->getGrammar() instanceof PostgresGrammar) {
                $query->whereRaw(new TextCastColumnComparison(
                    $query->getGrammar()->wrap(AuthTables::TenantMemberships.'.subject_id'),
                    $query->getGrammar()->wrap($principalKey),
                ));
            } else {
                $query->whereColumn(AuthTables::TenantMemberships.'.subject_id', $principalKey);
            }
            $query
                ->where(AuthTables::TenantMemberships.'.subject_type', $principal->getMorphClass())
                ->where(AuthTables::TenantMemberships.'.tenant_id', $tenant)
                ->where(AuthTables::TenantMemberships.'.status', 'active');
        });
    }

    /**
     * Define package permission casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_system' => 'boolean',
            'metadata' => 'array',
        ];
    }
}
