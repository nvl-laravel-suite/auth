<?php

declare(strict_types=1);

use Nvl\Auth\Tests\DisabledAuthProviderTestCase;
use Nvl\Auth\Tests\LegacyAuthTenancyTestCase;
use Nvl\Auth\Tests\TenancyTestCase;
use Nvl\Auth\Tests\TestCase;

$legacyFeatureFiles = glob(__DIR__.'/Feature/*Test.php') ?: [];
uses(TestCase::class)->in(...$legacyFeatureFiles);
uses(TestCase::class)->in('Unit');
uses(TenancyTestCase::class)->in('Feature/Tenancy');
uses(LegacyAuthTenancyTestCase::class)->in('Feature/TenancyAdoption');
uses(DisabledAuthProviderTestCase::class)->in('Provider');
