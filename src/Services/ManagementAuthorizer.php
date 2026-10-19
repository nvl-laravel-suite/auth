<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

/**
 * Applies the host's business authorization contract consistently.
 */
final readonly class ManagementAuthorizer
{
    /**
     * Create a management authorizer.
     */
    public function __construct(private AuthManagementAccess $access, private AuthOperationBoundary $operations,
        private AuthOwnerAdmission $owners,
        private OwnershipContext $ownership,
        private AuthOwnershipState $state,
    ) {}

    /**
     * Require a package management ability.
     */
    public function authorize(
        Authenticatable $actor,
        string $ability,
        mixed $target = null,
    ): void {
        if ($this->state->configured()) {
            $snapshot = $this->ownership->snapshot();
            if ($snapshot->publicSite !== null) {
                throw new OwnershipViolation('Public site access cannot grant Auth management authority.');
            }
            if ($snapshot->mode === OwnershipContextMode::Owner) {
                $this->owners->assertAllowed($actor);
            } elseif ($snapshot->mode !== OwnershipContextMode::Central) {
                throw new OwnershipViolation('Auth management requires explicit owner or central admission.');
            }
        }
        if (! $this->access->allows($actor, $ability, $target)) {
            throw new AuthException('forbidden', 'This Auth management operation is not authorized.', 403);
        }
        if (str_starts_with($ability, 'nvl.auth.users.') || str_starts_with($ability, 'nvl.auth.clients.')
            || $ability === 'nvl.auth.rbac.managePermissions') {
            $this->operations->requirePlatformAdministration();
        }
    }
}
