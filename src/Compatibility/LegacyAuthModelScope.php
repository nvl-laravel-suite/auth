<?php

declare(strict_types=1);

namespace Nvl\Auth\Compatibility;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use Nvl\Support\Ownership\Services\OwnershipScope;
use Nvl\Support\Ownership\Services\PersistedOwnershipStorage;

/** Preserves the historical explicit Auth boundaries until native storage is adopted. @internal
 * @implements Scope<Model>
 */
final readonly class LegacyAuthModelScope implements Scope
{
    /** Retain only the pre-adoption legacy behavior; native markers always deny this fallback. */
    public static function permitsLegacy(Model $model): bool
    {
        if (config('nvl-tenancy.enabled') !== true || config('nvl-auth.ownership.scoped') === true) {
            return false;
        }
        (new PersistedOwnershipStorage)->assertUnadopted($model->getConnection(), physicalTable: $model->getTable());

        return true;
    }

    /** @param Builder<covariant Model> $builder */
    public function apply(Builder $builder, Model $model): void
    {
        if (self::permitsLegacy($model)) {
            return;
        }
        (new OwnershipScope)->apply($builder, $model);
    }
}
