<?php

declare(strict_types=1);

use Nvl\Auth\Tests\DisabledAuthProviderTestCase;
use Nvl\Auth\Tests\FreshAdoptedAuthProviderTestCase;
use Nvl\Auth\Tests\HostAuthAdoptionTestCase;
use Nvl\Auth\Tests\LegacyAuthTenancyTestCase;
use Nvl\Auth\Tests\TenancyTestCase;
use Nvl\Auth\Tests\TestCase;

$legacyFeatureFiles = glob(__DIR__.'/Feature/*Test.php') ?: [];
uses(TestCase::class)->in(...$legacyFeatureFiles);
uses(TestCase::class)->in(__DIR__.'/Unit');
uses(TenancyTestCase::class)->in(__DIR__.'/Feature/Tenancy');
uses(LegacyAuthTenancyTestCase::class)->in(__DIR__.'/Feature/TenancyAdoption');
$disabledProviderFiles = array_filter(
    glob(__DIR__.'/Provider/*Test.php') ?: [],
    static fn (string $file): bool => basename($file) !== 'AdoptedStorageBootTest.php',
);
uses(DisabledAuthProviderTestCase::class)->in(...$disabledProviderFiles);
uses(FreshAdoptedAuthProviderTestCase::class)->in(__DIR__.'/Provider/AdoptedStorageBootTest.php');
uses(HostAuthAdoptionTestCase::class)->in(__DIR__.'/Adoption');
