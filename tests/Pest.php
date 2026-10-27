<?php

declare(strict_types=1);

use Nvl\Auth\Tests\DisabledAuthProviderTestCase;
use Nvl\Auth\Tests\FreshAdoptedAuthProviderTestCase;
use Nvl\Auth\Tests\HostAuthAdoptionTestCase;
use Nvl\Auth\Tests\NativeOwnerScenarioTestCase;
use Nvl\Auth\Tests\SecurityConcurrencyTestCase;
use Nvl\Auth\Tests\TestCase;

$raceFiles = [__DIR__.'/Feature/AuthenticationProofLifecycleTest.php', __DIR__.'/Feature/AuthenticationAssuranceTest.php', __DIR__.'/Feature/CredentialConcurrencyTest.php', __DIR__.'/Feature/InvitationRegistrationRaceTest.php', __DIR__.'/Feature/SchemaOwnershipTest.php'];
uses(SecurityConcurrencyTestCase::class)->in(...$raceFiles);
$legacyFeatureFiles = array_diff(glob(__DIR__.'/Feature/*Test.php') ?: [], $raceFiles);
uses(TestCase::class)->in(...$legacyFeatureFiles);
uses(TestCase::class)->in(__DIR__.'/Unit');
$nativeOwnerScenarios = [
    __DIR__.'/Ownership/NativeMembershipLifecycleTest.php',
    __DIR__.'/Ownership/NativePrincipalBoundaryTest.php',
    __DIR__.'/Ownership/NativeAuthenticationIntentTest.php',
    __DIR__.'/Ownership/NativeInvitationAcceptanceTest.php',
    __DIR__.'/Ownership/NativeInvitationBootstrapTest.php',
    __DIR__.'/Ownership/NativeQueuedDeliveryContextTest.php',
];
uses(NativeOwnerScenarioTestCase::class)->in(...$nativeOwnerScenarios);

$disabledProviderFiles = array_filter(
    glob(__DIR__.'/Provider/*Test.php') ?: [],
    static fn (string $file): bool => basename($file) !== 'AdoptedStorageBootTest.php',
);
uses(DisabledAuthProviderTestCase::class)->in(...$disabledProviderFiles);
uses(FreshAdoptedAuthProviderTestCase::class)->in(__DIR__.'/Provider/AdoptedStorageBootTest.php');
uses(HostAuthAdoptionTestCase::class)->in(__DIR__.'/Adoption');
