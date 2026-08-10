<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;

/**
 * Lists package principals through bounded management filters.
 */
final readonly class ListUsersAction
{
    /**
     * Create the principal listing use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthConfiguration $configuration,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /**
     * Return a paginated principal inventory.
     *
     * @return LengthAwarePaginator<int, User>
     */
    public function execute(
        Authenticatable $actor,
        ?string $search = null,
        ?bool $active = null,
        string $trashed = 'without',
        ?string $role = null,
        int $perPage = 25,
    ): LengthAwarePaginator {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.users.viewAny');

        if (! in_array($trashed, ['without', 'with', 'only'], true)) {
            throw new AuthException('invalid_user_filter', 'The trashed user filter is invalid.', 422);
        }

        if (($search !== null && mb_strlen($search) > 160)
            || ($role !== null && mb_strlen($role) > 160)) {
            throw new AuthException('invalid_user_filter', 'User search filters must not exceed 160 characters.', 422);
        }

        $maximum = $this->configuration->positiveInteger(
            'features.principal_management.settings.maximum_per_page',
            100,
        );
        $query = $this->users->query($trashed !== 'without')
            ->with(['roles:id,name,guard_name', 'permissions:id,name,guard_name'])
            ->withCount(['roles', 'permissions']);

        if ($trashed === 'only') {
            $query->onlyTrashed();
        }

        if ($search !== null && trim($search) !== '') {
            $term = '%'.trim($search).'%';
            $name = $this->attributes->column(PrincipalAttribute::Name);
            $email = $this->attributes->column(PrincipalAttribute::Email);
            $query->where(static function (Builder $searchQuery) use ($email, $name, $term): void {
                $searchQuery->where($name, 'like', $term)->orWhere($email, 'like', $term);
            });
        }

        if ($active !== null) {
            $query->where($this->attributes->column(PrincipalAttribute::Active), $active);
        }

        if ($role !== null && trim($role) !== '') {
            $query->role(trim($role));
        }

        return $query
            ->latest($this->attributes->column(PrincipalAttribute::CreatedAt))
            ->paginate(max(1, min($perPage, $maximum)));
    }
}
