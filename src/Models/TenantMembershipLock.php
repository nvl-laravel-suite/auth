<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Support\Config\PackageStorage;

/**
 * Stable serialization row retained for the complete lifetime of a tenant.
 *
 * @property string $tenant_id
 */
final class TenantMembershipLock extends AuthModel
{
    public const string TABLE = AuthTables::TenantMembershipLocks;

    /** @var string */
    protected $table = self::TABLE;

    /** @var string */
    protected $primaryKey = 'tenant_id';

    /** @var list<string> */
    protected $fillable = ['tenant_id'];

    /** The tenant identifier is supplied explicitly rather than generated. */
    /** @return list<string> */
    public function uniqueIds(): array
    {
        return [];
    }

    /** Resolve the configured package storage table. */
    public function getTable(): string
    {
        return AuthTables::get(AuthTables::TenantMembershipLocks);
    }

    /** Resolve the package connection through shared infrastructure defaults. */
    public function getConnectionName(): ?string
    {
        return PackageStorage::connectionName($this->connection ?? PackageStorage::connection('auth') ?? parent::getConnectionName());
    }
}
