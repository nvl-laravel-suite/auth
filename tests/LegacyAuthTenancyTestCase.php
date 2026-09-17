<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

/** Leaves Auth tenant adoption stages under each schema test's explicit control. */
abstract class LegacyAuthTenancyTestCase extends TenancyTestCase
{
    protected function activateEmptyAuthTenancy(): void {}

    protected function deactivateMaintenanceAfterSetup(): bool
    {
        return false;
    }
}
