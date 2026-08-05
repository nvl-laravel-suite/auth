<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;

/**
 * Applies package RBAC payloads through Spatie Permission's configured model trait.
 */
final readonly class RbacManager
{
    /**
     * Create the Spatie Permission integration.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthModelRegistry $models,
    ) {}

    /**
     * Assign invitation roles and direct permissions to a configured principal.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function assign(
        Authenticatable $subject,
        array $roles,
        array $permissions,
    ): void {
        if ($roles === [] && $permissions === []) {
            return;
        }

        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);

        if (! $subject instanceof Model
            || ! method_exists($subject, 'assignRole')
            || ! method_exists($subject, 'givePermissionTo')) {
            throw AuthException::invalidConfiguration(
                'RBAC payloads require the configured principal to use Spatie Permission HasRoles.',
            );
        }

        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $connections = [
            (new Invitation)->getConnection()->getName(),
            $subject->getConnection()->getName(),
            (new $roleClass)->getConnection()->getName(),
            (new $permissionClass)->getConnection()->getName(),
        ];

        if (count(array_unique($connections)) !== 1) {
            throw AuthException::invalidConfiguration(
                'Invitation RBAC payloads require Auth principals, roles, and permissions on one database connection.',
            );
        }

        if ($roles !== []) {
            $subject->assignRole($roles);
        }

        if ($permissions !== []) {
            $subject->givePermissionTo($permissions);
        }
    }
}
