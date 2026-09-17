<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\Grammars\PostgresGrammar;
use Nvl\Auth\Database\Factories\RoleFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Relations\TextCastColumnComparison;
use Spatie\Permission\Models\Role as SpatieRole;

/**
 * Provides the package-owned, hierarchical Spatie Permission role model.
 *
 * @property string $id
 * @property string $tenant_id
 * @property string $name
 * @property string $guard_name
 * @property string|null $display_name
 * @property string|null $description
 * @property string|null $parent_id
 * @property int $priority
 * @property bool $is_system
 * @property array<string, mixed>|null $metadata
 * @property-read int|null $users_count
 * @property-read int|null $permissions_count
 */
#[UseFactory(RoleFactory::class)]
class Role extends SpatieRole
{
    /** @use HasFactory<RoleFactory> */
    use HasFactory;

    use HasUuids;

    public const TABLE = AuthTables::Roles;

    /** @var string */
    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = [
        'tenant_id',
        'name',
        'guard_name',
        'display_name',
        'description',
        'parent_id',
        'priority',
        'is_system',
        'metadata',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'priority' => 0,
        'is_system' => false,
    ];

    /**
     * Resolve the configured package table.
     */
    public function getTable(): string
    {
        $configured = config('nvl-auth.tables.roles');

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

    /** @return BelongsTo<static, $this> */
    public function parent(): BelongsTo
    {
        $relation = $this->belongsTo(static::class, 'parent_id');

        return config('tenancy.enabled') === true ? $relation->where('tenant_id', $this->tenant_id) : $relation;
    }

    /** @return HasMany<static, $this> */
    public function children(): HasMany
    {
        $relation = $this->hasMany(static::class, 'parent_id');
        if (config('tenancy.enabled') === true) {
            $relation->where('tenant_id', $this->tenant_id);
        }

        return $relation->orderByDesc('priority')->orderBy('name');
    }

    /** Constrain inverse assignments to the active team and membership. */
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
     * Define package role casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'priority' => 'integer',
            'is_system' => 'boolean',
            'metadata' => 'array',
        ];
    }
}
