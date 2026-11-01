<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Laravel\Sanctum\PersonalAccessToken as SanctumPersonalAccessToken;
use Nvl\Auth\Database\Factories\PersonalAccessTokenFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\Traits\HasAuthOwnership;
use Nvl\Auth\Traits\SerializesAuthTimestamps;
use Nvl\Support\Config\PackageStorage;
use Nvl\Support\Ownership\Contracts\Ownable;

/**
 * Stores Sanctum tokens in the package-owned namespaced token table.
 *
 * @property string $id
 * @property string $tokenable_type
 * @property string $tokenable_id
 * @property string $name
 * @property string $token
 * @property list<string>|null $abilities
 *
 * @api
 *
 * @nvl-consumer-read id
 *
 * @property string|null $owner_scope_key
 * @property string|null $owner_reference
 */
#[UseFactory(PersonalAccessTokenFactory::class)]
class PersonalAccessToken extends SanctumPersonalAccessToken implements Ownable
{
    use HasAuthOwnership;

    /** @use HasFactory<PersonalAccessTokenFactory> */
    use HasFactory;

    use HasUuids;
    use SerializesAuthTimestamps;

    public const TABLE = AuthTables::PersonalAccessTokens;

    /** @var string */
    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = [
        'name', 'token', 'abilities', 'expires_at',
    ];

    /** @return array<string, class-string<AuthInstantCast>> */
    protected function casts(): array
    {
        return [
            'created_at' => AuthInstantCast::class,
            'updated_at' => AuthInstantCast::class,
            'last_used_at' => AuthInstantCast::class,
            'expires_at' => AuthInstantCast::class,
        ];
    }

    /**
     * Resolve the configured package token table.
     */
    public function getTable(): string
    {
        $configured = config('nvl-auth.tables.personal_access_tokens');

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : self::TABLE;
    }

    /**
     * Resolve the immutable package operational connection.
     */
    public function getConnectionName(): ?string
    {
        return PackageStorage::connectionName($this->connection ?? PackageStorage::connection('auth') ?? parent::getConnectionName());
    }

    /**
     * Return the runtime package fixture factory.
     *
     * @internal
     */
    protected static function newFactory(): PersonalAccessTokenFactory
    {
        return PersonalAccessTokenFactory::new();
    }
}
