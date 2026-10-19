<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

/** Exercises host-owned admission without installing NVL membership storage. */
abstract class HostPolicyOwnerScopeTestCase extends OwnerScopeTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('nvl-auth.features.memberships.enabled', false);
    }
}
