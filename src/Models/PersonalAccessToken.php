<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Laravel\Sanctum\PersonalAccessToken as SanctumPersonalAccessToken;
use Nvl\Auth\Database\Factories\PersonalAccessTokenFactory;

/**
 * Stores Sanctum tokens in the package-owned namespaced token table.
 *
 * @property string $id
 * @property string $tokenable_type
 * @property string $tokenable_id
 * @property string $name
 * @property string $token
 * @property list<string>|null $abilities
 */
#[UseFactory(PersonalAccessTokenFactory::class)]
class PersonalAccessToken extends SanctumPersonalAccessToken
{
    /** @use HasFactory<PersonalAccessTokenFactory> */
    use HasFactory;

    use HasUuids;

    public const TABLE = 'nvl_auth_personal_access_tokens';

    /** @var string */
    protected $keyType = 'string';

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
        $configured = config('nvl-auth.connection');

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : parent::getConnectionName();
    }
}
