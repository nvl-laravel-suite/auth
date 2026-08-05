<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Resolves persisted morph references for conventional Eloquent subjects.
 */
final class EloquentAuthSubjectResolver implements AuthSubjectResolver
{
    /** {@inheritDoc} */
    public function resolve(SubjectReference $reference): ?Authenticatable
    {
        $modelClass = Relation::getMorphedModel($reference->type) ?? $reference->type;

        if (! class_exists($modelClass)
            || ! is_a($modelClass, Model::class, true)
            || ! is_a($modelClass, Authenticatable::class, true)) {
            return null;
        }

        /** @var Model&Authenticatable $model */
        $model = new $modelClass;
        $subject = $model->newQuery()->find($reference->identifier);

        return $subject instanceof Authenticatable ? $subject : null;
    }
}
