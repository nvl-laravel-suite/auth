<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\OwnerAuthenticationIntent;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\OwnerMembershipLock;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Support\Models\ConfiguredModelResolver;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;
use Nvl\Support\Ownership\ValueObjects\OwnershipDefinition;
use Nvl\Support\Ownership\ValueObjects\OwnershipResourceDefinition;

/** Declares the optional owned Auth graph while keeping global credentials and vocabulary global. @internal */
final readonly class AuthResourceRegistrar
{
    public function __construct(private AuthModelRegistry $models) {}

    public function register(OwnershipResourceRegistry $resources): void
    {
        $owned = config('nvl-auth.ownership.scoped') === true;
        $memberships = $owned && config('nvl-auth.features.memberships.enabled') === true;
        if ($owned) {
            $this->models->userClass();
            $this->models->rbacPrincipalClass();
            $resolver = new ConfiguredModelResolver;
            foreach ([[$this->models->roleClass(), Role::class], [$this->models->personalAccessTokenClass(), PersonalAccessToken::class], ...($memberships ? [[$this->models->ownerMembershipClass(), OwnerMembership::class]] : [])] as [$class, $base]) {
                $resolver->assertOwnershipCapabilities(new $class, new $base);
            }
        }
        foreach ([
            'auth.memberships' => [$memberships ? $this->models->ownerMembershipClass() : TenantMembership::class, $memberships, false],
            'auth.membership_locks' => [$memberships ? OwnerMembershipLock::class : TenantMembershipLock::class, $memberships, false],
            'auth.authentication_intents' => [$owned ? OwnerAuthenticationIntent::class : TenantAuthenticationIntent::class, $owned, false],
            'auth.roles' => [$this->models->roleClass(), $owned, true],
            'auth.invitations' => [Invitation::class, $owned, true],
            'auth.tokens' => [$this->models->personalAccessTokenClass(), $owned, true],
            'auth.challenges' => [Challenge::class, $owned, true],
            'auth.audits' => [AuthAudit::class, $owned, true],
            'auth.permissions' => [$this->models->permissionClass(), false, true],
        ] as $key => [$model, $captured, $central]) {
            $immutable = match ($key) {
                'auth.memberships' => ['subject_type', 'subject_id'],
                'auth.tokens' => ['tokenable_type', 'tokenable_id', 'token'],
                default => [],
            };
            $resources->register(new OwnershipResourceDefinition($key, 'auth', $model, $captured ? OwnershipDefinition::captured() : OwnershipDefinition::unscoped(), allowsCentral: $central, immutableFields: $captured ? $immutable : []));
        }
    }
}
