<?php

declare(strict_types=1);

use Nvl\Auth\Tests\DisabledAuthProviderTestCase;
use Nvl\Auth\Tests\FreshAdoptedAuthProviderTestCase;
use Nvl\Auth\Tests\HostAuthAdoptionTestCase;
use Nvl\Auth\Tests\NativeOwnerScenarioTestCase;
use Nvl\Auth\Tests\SecurityConcurrencyTestCase;
use Nvl\Auth\Tests\StatefulAuthTestCase;
use Nvl\Auth\Tests\TestCase;

$raceFiles = [__DIR__.'/Feature/RegistrationConcurrencyTest.php', __DIR__.'/Feature/EmailIdentityTest.php', __DIR__.'/Feature/EmailIdentityAdoptionTest.php', __DIR__.'/Feature/EmailVerificationSecurityTest.php', __DIR__.'/Feature/PasswordMutationSecurityTest.php', __DIR__.'/Feature/WebauthnPasskeyCeremonyTest.php', __DIR__.'/Feature/PasskeyLifecycleTest.php', __DIR__.'/Feature/TotpAndRecoveryCodeTest.php', __DIR__.'/Feature/PrincipalManagementTest.php', __DIR__.'/Feature/SocialIdentityLifecycleTest.php', __DIR__.'/Feature/NativeAuthCoreTest.php', __DIR__.'/Feature/RecentAuthenticationTest.php', __DIR__.'/Feature/SensitiveOperationAdmissionTest.php', __DIR__.'/Feature/AuthenticationProofLifecycleTest.php', __DIR__.'/Feature/AuthenticationAssuranceTest.php', __DIR__.'/Feature/CredentialConcurrencyTest.php', __DIR__.'/Feature/InvitationRegistrationRaceTest.php', __DIR__.'/Feature/SchemaOwnershipTest.php'];
uses(SecurityConcurrencyTestCase::class)->in(...$raceFiles);
$statefulFiles = [__DIR__.'/Feature/SocialRegistrationTest.php', __DIR__.'/Feature/SocialAuthenticationTest.php', __DIR__.'/Feature/LifecyclePipelineTest.php', __DIR__.'/Feature/RegistrationCompositionTest.php', __DIR__.'/Feature/SocialiteWorkerIsolationTest.php', __DIR__.'/Feature/StatefulTransactionBoundaryTest.php', __DIR__.'/Feature/AuthenticationAndVerificationTest.php', __DIR__.'/Feature/PrincipalAttributeMappingTest.php', __DIR__.'/Feature/ConsumerContractBindingTest.php', __DIR__.'/Feature/HttpApiTest.php', __DIR__.'/Feature/FeatureAdmissionTest.php'];
uses(StatefulAuthTestCase::class)->in(...$statefulFiles);
$legacyFeatureFiles = array_diff(glob(__DIR__.'/Feature/*Test.php') ?: [], $raceFiles, $statefulFiles);
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
