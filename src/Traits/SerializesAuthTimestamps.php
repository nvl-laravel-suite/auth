<?php

declare(strict_types=1);

namespace Nvl\Auth\Traits;

use Nvl\Auth\Support\AuthInstantCast;

/** Native framework bulk timestamps must retain their absolute instant on the actual source.
 *
 * @internal
 */
trait SerializesAuthTimestamps
{
    /**
     * Pass native instants directly to their cast before Laravel loses the input offset.
     *
     * @param  string  $key
     */
    protected function isDateAttribute(mixed $key): bool
    {
        return ($this->getCasts()[$key] ?? null) !== AuthInstantCast::class && parent::isDateAttribute($key);
    }

    /**
     * Encode framework touch, upsert and query soft-delete timestamps independently of host date casts.
     *
     * @internal
     */
    public function freshTimestampString(): string
    {
        return AuthInstantCast::forQuery($this->getConnection(), $this->freshTimestamp());
    }
}
