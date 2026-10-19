<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\PostgresGrammar;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Relations\TextCastColumnComparison;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;

/** Builds native inverse RBAC queries without exposing another owner's assignments. @internal */
final readonly class OwnerRbacRelations
{
    public function __construct(private AuthModelRegistry $models, private OwnershipContext $context, private OwnershipReadiness $readiness) {}

    /** @template TOwner of Model
     * @param  TOwner  $resource
     * @param  'role'|'permission'  $kind
     * @return MorphToMany<Model&Authenticatable, TOwner>
     */
    public function users(Model $resource, string $kind): BelongsToMany
    {
        $this->readiness->assertActive('auth.roles');
        $principalClass = $this->models->rbacPrincipalClass();
        $related = new $principalClass;
        if ($related->getConnection() !== $resource->getConnection()) {
            throw AuthException::invalidConfiguration('Native RBAC inverse queries require one actual source.');
        }
        $table = config('permission.table_names.model_has_'.($kind === 'role' ? 'roles' : 'permissions'));
        $foreign = config('permission.column_names.'.$kind.'_pivot_key', $kind.'_id');
        $morph = config('permission.column_names.model_morph_key', 'model_id');
        if (! is_string($table) || ! is_string($foreign) || ! is_string($morph)) {
            throw AuthException::invalidConfiguration('Native RBAC requires explicit inverse table metadata.');
        }
        $relation = $resource->morphedByMany($principalClass, 'model', $table, $foreign, $morph);
        if ($this->context->snapshot()->mode === OwnershipContextMode::Central) {
            $relation->wherePivot('owner_scope_key', 'central');

            return $relation;
        }
        $scope = $this->context->requireOwner()->scopeKey();
        $relation->wherePivot('owner_scope_key', $scope);
        if (config('nvl-auth.features.memberships.enabled') !== true) {
            return $relation;
        }
        $class = $this->models->ownerMembershipClass();
        $membership = new $class;
        if ($membership->getConnection() !== $resource->getConnection()) {
            throw AuthException::invalidConfiguration('Native membership projection requires one actual source.');
        }
        $membershipTable = $membership->getTable();

        $relation->getQuery()->whereExists(static function (Builder $query) use ($membershipTable, $related, $scope): void {
            $query->selectRaw('1')->from($membershipTable);
            $subject = $query->getGrammar()->wrap($membershipTable.'.subject_id');
            $principal = $query->getGrammar()->wrap($related->qualifyColumn($related->getKeyName()));
            if ($query->getGrammar() instanceof PostgresGrammar) {
                $query->whereRaw(new TextCastColumnComparison($subject, $principal));
            } else {
                $query->whereColumn($membershipTable.'.subject_id', $related->qualifyColumn($related->getKeyName()));
            }
            $query->where($membershipTable.'.subject_type', $related->getMorphClass())
                ->where($membershipTable.'.owner_scope_key', $scope)->where($membershipTable.'.status', 'active');
        });

        return $relation;
    }
}
