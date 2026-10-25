<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\Pivot;
use Nvl\Auth\Database\Factories\RoleFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Services\AuthOwnershipState;
use Nvl\Auth\Services\OwnerRbacRelations;
use Nvl\Auth\Traits\HasAuthOwnership;
use Nvl\Support\Config\PackageStorage;
use Nvl\Support\Ownership\Contracts\Ownable;
use Spatie\Permission\Models\Role as SpatieRole;

/**
 * Provides the package-owned, hierarchical Spatie Permission role model.
 *
 * @property string $id
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
 *
 * @api
 *
 * @property string|null $owner_scope_key
 * @property string|null $owner_reference
 */
#[UseFactory(RoleFactory::class)]
class Role extends SpatieRole implements Ownable
{
    use HasAuthOwnership;

    /** @use HasFactory<RoleFactory> */
    use HasFactory;

    use HasUuids;

    public const TABLE = AuthTables::Roles;

    /** @var string */
    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = ['name', 'guard_name', 'display_name', 'description', 'parent_id', 'priority', 'is_system', 'metadata'];

    /** @var array<string, mixed> */
    protected $attributes = ['priority' => 0, 'is_system' => false];

    /**
     * Resolve the configured package table.
     */
    public function getTable(): string
    {
        $configured = config('nvl-auth.tables.roles');

        return is_string($configured) && trim($configured) !== '' ? trim($configured) : self::TABLE;
    }

    /**
     * Resolve the immutable package operational connection.
     */
    public function getConnectionName(): ?string
    {
        return PackageStorage::connectionName($this->connection ?? PackageStorage::connection('auth') ?? parent::getConnectionName());
    }

    /** @return BelongsTo<static, $this> */
    public function parent(): BelongsTo
    {
        $relation = $this->belongsTo(static::class, 'parent_id');

        return $relation;
    }

    /** @return HasMany<static, $this> */
    public function children(): HasMany
    {
        $relation = $this->hasMany(static::class, 'parent_id');

        return $relation->orderByDesc('priority')->orderBy('name');
    }

    /** @return BelongsToMany<covariant Model, $this, covariant Pivot> */
    public function users(): BelongsToMany
    {
        if (Container::getInstance()->make(AuthOwnershipState::class)->native()) {
            return Container::getInstance()->make(OwnerRbacRelations::class)->users($this, 'role');
        }

        return parent::users();
    }

    /**
     * Define package role casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['priority' => 'integer', 'is_system' => 'boolean', 'metadata' => 'array'];
    }

    /** Return the runtime package fixture factory.
     *
     * @internal
     */
    protected static function newFactory(): RoleFactory
    {
        return RoleFactory::new();
    }
}
