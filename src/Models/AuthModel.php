<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use LogicException;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\Traits\SerializesAuthTimestamps;
use Nvl\Support\Config\PackageStorage;

/**
 * Provides shared connection and UUID behavior for package-owned records.
 *
 * @property string $id
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
abstract class AuthModel extends Model
{
    use HasUuids;
    use SerializesAuthTimestamps;

    /**
     * Disable integer key assumptions.
     *
     * @var string
     */
    protected $keyType = 'string';

    /** @var array<string, string> */
    protected $casts = [
        'created_at' => AuthInstantCast::class,
        'updated_at' => AuthInstantCast::class,
    ];

    /**
     * Resolve the immutable package operational connection.
     */
    public function getConnectionName(): ?string
    {
        return PackageStorage::connectionName($this->connection ?? PackageStorage::connection('auth') ?? parent::getConnectionName());
    }

    /**
     * Return the model's required UUID identifier.
     */
    public function identifier(): string
    {
        $identifier = $this->getAttribute($this->getKeyName());

        if (! is_string($identifier) || $identifier === '') {
            throw new LogicException('Persisted Auth models require a UUID identifier.');
        }

        return $identifier;
    }
}
