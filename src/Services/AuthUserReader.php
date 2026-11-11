<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Relations\Relation;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Support\LiteralSearch;

/**
 * Complete native AuthUserReader operations.
 *
 * @api
 */
final readonly class AuthUserReader
{
    /** Create the authorized principal reader. */
    public function __construct(private FeatureGate $features, private ManagementAuthorizer $authorization, private UserLocator $users, private AuthConfiguration $configuration, private PrincipalAttributeMapper $attributes, private AuthOperationBoundary $operations) {}

    /**
     * Return a paginated principal inventory.
     *
     * @return LengthAwarePaginator<int, User>
     */
    public function paginate(Authenticatable $actor, ?string $search = null, ?bool $active = null, string $trashed = 'without', ?string $role = null, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.users.viewAny');
        if (! in_array($trashed, ['without', 'with', 'only'], true)) {
            throw new AuthException('invalid_user_filter', 'The trashed user filter is invalid.', 422);
        }
        if ($search !== null && mb_strlen($search) > 160 || $role !== null && mb_strlen($role) > 160) {
            throw new AuthException('invalid_user_filter', 'User search filters must not exceed 160 characters.', 422);
        }
        $maximum = $this->configuration->positiveInteger('features.principal_management.settings.maximum_per_page', 100);
        $query = $this->users->query($trashed !== 'without');
        if (config('nvl-auth.features.rbac.enabled') === true) {
            foreach (['roles', 'permissions'] as $relation) {
                if (! method_exists($query->getModel(), $relation)) {
                    throw AuthException::invalidConfiguration('The selected principal must expose its configured Permission relations.');
                }
                $query->getRelation($relation);
                $query->setEagerLoads([
                    ...$query->getEagerLoads(),
                    $relation => static function (Relation $relationQuery): void {
                        $related = $relationQuery->getRelated();
                        $relationQuery->getQuery()->select($related->qualifyColumns(['id', 'name', 'guard_name']));
                    },
                ])->withAggregate($relation, '*', 'count');
            }
        }
        if ($trashed === 'only') {
            $query->onlyTrashed();
        }
        if ($search !== null && trim($search) !== '') {
            LiteralSearch::contains($query, [$this->attributes->column(PrincipalAttribute::Name), $this->attributes->column(PrincipalAttribute::Email)], trim($search));
        }
        if ($active !== null) {
            $query->where($this->attributes->column(PrincipalAttribute::Active), $active);
        }
        if ($role !== null && trim($role) !== '') {
            $model = $query->getModel();
            if (! method_exists($model, 'scopeRole')) {
                throw AuthException::invalidConfiguration('Role filtering requires the configured principal Permission capability.');
            }
            $model->scopeRole($query, trim($role));
        }

        return $query->latest($this->attributes->column(PrincipalAttribute::CreatedAt))->paginate(max(1, min($perPage, $maximum)));
    }

    /** Return the authenticated principal. */
    public function profile(Authenticatable $subject): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->operations->central(AuthIdentityOperation::Profile, $subject);

        return $this->users->authenticated($subject)->load(config('nvl-auth.features.rbac.enabled') === true ? ['roles', 'permissions'] : []);
    }

    /** Return one principal. */
    public function find(Authenticatable $actor, User|string $user): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $user = $this->users->find($user, true);
        $this->authorization->authorize($actor, 'nvl.auth.users.view', $user);

        return $user->load(config('nvl-auth.features.rbac.enabled') === true ? ['roles', 'permissions'] : []);
    }

    /**
     * Find enabled principals by name or email.
     *
     * @return Collection<int, User>
     */
    public function suggest(Authenticatable $actor, string $search, ?int $limit = null): Collection
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.users.viewAny');
        $search = trim($search);
        if ($search === '' || mb_strlen($search) > 160) {
            throw new AuthException('invalid_user_search', 'User suggestions require between one and 160 search characters.', 422);
        }
        $maximum = $this->configuration->positiveInteger('features.principal_management.settings.suggestion_limit', 20);
        $id = $this->attributes->column(PrincipalAttribute::Id);
        $name = $this->attributes->column(PrincipalAttribute::Name);
        $email = $this->attributes->column(PrincipalAttribute::Email);
        $active = $this->attributes->column(PrincipalAttribute::Active);

        $query = $this->users->query()->select([$id, $name, $email, $active])->where($active, true);
        LiteralSearch::contains($query, [$name, $email], $search);

        return $query->orderBy($name)->limit(max(1, min($limit ?? $maximum, $maximum)))->get();
    }
}
