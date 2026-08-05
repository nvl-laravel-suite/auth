<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Collection;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;

/**
 * Returns a minimal, bounded principal suggestion list.
 */
final readonly class SuggestUsersAction
{
    /**
     * Create the suggestion use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthConfiguration $configuration,
    ) {}

    /**
     * Find enabled principals by name or email.
     *
     * @return Collection<int, User>
     */
    public function execute(Authenticatable $actor, string $search, ?int $limit = null): Collection
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.users.viewAny');
        $search = trim($search);

        if ($search === '' || mb_strlen($search) > 160) {
            throw new AuthException('invalid_user_search', 'User suggestions require between one and 160 search characters.', 422);
        }

        $maximum = $this->configuration->positiveInteger(
            'features.principal_management.settings.suggestion_limit',
            20,
        );
        $term = "%{$search}%";

        return $this->users->query()
            ->select(['id', 'name', 'email', 'is_active'])
            ->where('is_active', true)
            ->where(static function ($query) use ($term): void {
                $query->where('name', 'like', $term)->orWhere('email', 'like', $term);
            })
            ->orderBy('name')
            ->limit(max(1, min($limit ?? $maximum, $maximum)))
            ->get();
    }
}
