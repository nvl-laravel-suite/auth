<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use LogicException;

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

    /**
     * Disable integer key assumptions.
     *
     * @var string
     */
    protected $keyType = 'string';

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
