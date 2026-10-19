<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerMembership;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerRole;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerToken;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerUser;

/** Compiles a configured consumer model before the owner graph is frozen. */
abstract class ConfiguredOwnerScopeTestCase extends OwnerScopeTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set([
            'nvl-auth.features.memberships.models.membership' => ConfiguredOwnerMembership::class,
            'nvl-auth.features.rbac.models.role' => ConfiguredOwnerRole::class,
            'nvl-auth.features.rbac.models.principal' => ConfiguredOwnerUser::class,
            'nvl-auth.features.principal_management.models.user' => ConfiguredOwnerUser::class,
            'nvl-auth.features.api_tokens.models.personal_access_token' => ConfiguredOwnerToken::class,
            'auth.providers.users.model' => ConfiguredOwnerUser::class,
        ]);
    }
}
