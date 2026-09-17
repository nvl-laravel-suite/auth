<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Services\TenantBoundary;

/** Supplies canonical tenant role queries and assignment principal reloads. */
final readonly class AuthTenantRbacQueries
{
    public function __construct(
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
        private TenantBoundary $boundary,
        private TenantContext $context,
        private TenantMembershipAccess $membership,
        private MembershipPrincipalResolver $principals,
        private RbacPrincipalTracker $tracker,
    ) {}

    /** @return Builder<Role> */
    public function roles(): Builder
    {
        $class = $this->models->roleClass();

        /** @var Builder<Role> $query */
        $query = $this->boundary->query($class::query(), 'auth.roles');

        return $query->where('guard_name', $this->configuration->string('features.rbac.settings.guard', 'web'));
    }

    public function role(string $id, bool $lock = false): Role
    {
        $query = $this->roles()->whereKey($id);
        if ($lock) {
            $query->lockForUpdate();
        }

        return $query->first() ?? throw new AuthException('role_identifier_not_found', 'The tenant role is unavailable.', 404);
    }

    /** @return Builder<Permission> */
    public function permissions(): Builder
    {
        $class = $this->models->permissionClass();

        return $class::query()->where('guard_name', $this->configuration->string('features.rbac.settings.guard', 'web'));
    }

    public function assertAssignmentPrincipal(Authenticatable $principal): Authenticatable
    {
        $reloaded = $this->principals->resolve(SubjectReference::fromAuthenticatable($principal), true);
        $this->membership->assertMember($reloaded, $this->context->requireTenant());
        if (! $reloaded instanceof Model) {
            throw AuthException::invalidConfiguration('RBAC assignment principals must be Eloquent models.');
        }
        $reloaded->unsetRelation('roles')->unsetRelation('permissions');
        $this->tracker->track($reloaded);

        return $reloaded;
    }
}
