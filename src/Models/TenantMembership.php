<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\TenantMembershipFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Support\Config\PackageStorage;

/**
 * Stores one principal's lifecycle inside one tenant.
 *
 * @property string $tenant_id
 * @property string $subject_type
 * @property string $subject_id
 * @property MembershipStatus $status
 * @property bool $is_owner
 * @property int $revision
 *
 * @api
 */
#[UseFactory(TenantMembershipFactory::class)]
final class TenantMembership extends AuthModel
{
    /** @use HasFactory<TenantMembershipFactory> */
    use HasFactory;

    public const string TABLE = AuthTables::TenantMemberships;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = ['tenant_id', 'subject_type', 'subject_id', 'status', 'is_owner', 'revision'];

    /** @var array<string, mixed> */
    protected $attributes = ['status' => MembershipStatus::Active, 'is_owner' => false, 'revision' => 1];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'status' => MembershipStatus::class,
            'is_owner' => 'boolean',
            'revision' => 'integer',
        ];
    }

    /** Resolve the configured package storage table. */
    public function getTable(): string
    {
        return AuthTables::get(AuthTables::TenantMemberships);
    }

    /** Resolve the package connection through shared infrastructure defaults. */
    public function getConnectionName(): ?string
    {
        return PackageStorage::connectionName($this->connection ?? PackageStorage::connection('auth') ?? parent::getConnectionName());
    }

    /** Return the runtime package fixture factory.
     *
     * @internal
     */
    protected static function newFactory(): TenantMembershipFactory
    {
        return TenantMembershipFactory::new();
    }
}
