<?php

declare(strict_types=1);

namespace Nvl\Auth\Support;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/** Stores Auth instants as UTC seconds independently of the host timezone.
 * @implements CastsAttributes<CarbonImmutable, DateTimeInterface|string>
 *
 * @internal
 */
final class AuthInstantCast implements CastsAttributes
{
    public bool $withoutObjectCaching = true;

    /** @param array<string, mixed> $attributes */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?CarbonImmutable
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw new InvalidArgumentException('Auth timestamps require UTC strings.');
        }

        return CarbonImmutable::parse($value, 'UTC');
    }

    /** @param array<string, mixed> $attributes
     * @return array<string, string|null>
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): array
    {
        if ($value === null) {
            return [$key => null];
        }
        $date = $value instanceof DateTimeInterface ? CarbonImmutable::instance($value) : CarbonImmutable::parse($value, 'UTC');

        return [$key => $date->utc()->format('Y-m-d H:i:s')];
    }
}
