<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\OwnerAuthenticationIntent;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\OwnerMembershipLock;
use Nvl\Auth\Models\PendingEmailChange;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\PrincipalSecurityState;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Support\Models\ConfiguredModelResolver;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;
use Nvl\Support\Ownership\ValueObjects\OwnershipDefinition;
use Nvl\Support\Ownership\ValueObjects\OwnershipResourceDefinition;

/**
 * Declares the optional owned Auth graph while keeping global credentials and vocabulary global.
 *
 * @internal
 */
final readonly class AuthResourceRegistrar
{
    public function __construct(private AuthModelRegistry $models) {}

    public function register(OwnershipResourceRegistry $resources): void
    {
        $owned = config('nvl-auth.ownership.scoped') === true;
        $memberships = $owned && config('nvl-auth.features.memberships.enabled') === true;
        if ($owned) {
            $this->models->userClass();
            if (config('nvl-auth.features.rbac.enabled') === true) {
                $this->models->rbacPrincipalClass();
            }
            $resolver = new ConfiguredModelResolver;
            foreach ([...(class_exists(\Spatie\Permission\Models\Role::class) && is_string(config('permission.table_names.roles')) ? [[$this->models->roleClass(), Role::class]] : []), ...(class_exists(\Laravel\Sanctum\PersonalAccessToken::class) ? [[$this->models->personalAccessTokenClass(), PersonalAccessToken::class]] : []), ...($memberships ? [[$this->models->ownerMembershipClass(), OwnerMembership::class]] : [])] as [$class, $base]) {
                $resolver->assertOwnershipCapabilities(new $class, new $base);
            }
        }
        foreach ([
            ...($memberships ? ['auth.memberships' => [$this->models->ownerMembershipClass(), true, false], 'auth.membership_locks' => [OwnerMembershipLock::class, true, false]] : []),
            ...($owned ? ['auth.authentication_intents' => [OwnerAuthenticationIntent::class, true, false]] : []),
            ...(class_exists(\Spatie\Permission\Models\Role::class) && is_string(config('permission.table_names.roles')) ? ['auth.roles' => [$this->models->roleClass(), $owned, true], 'auth.permissions' => [$this->models->permissionClass(), false, true]] : []),
            'auth.invitations' => [Invitation::class, $owned, true],
            ...(class_exists(\Laravel\Sanctum\PersonalAccessToken::class) ? ['auth.tokens' => [$this->models->personalAccessTokenClass(), $owned, true]] : []),
            'auth.challenges' => [Challenge::class, $owned, true],
            'auth.remember_credentials' => [RememberCredential::class, false, true],
            'auth.browser_sessions' => [BrowserSession::class, false, true],
            'auth.pending_email_changes' => [PendingEmailChange::class, false, true],
            'auth.security_states' => [PrincipalSecurityState::class, false, true],
            'auth.audits' => [AuthAudit::class, $owned, true],
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
