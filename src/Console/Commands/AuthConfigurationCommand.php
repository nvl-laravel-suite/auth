<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Container\Container;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordPolicy;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthManagementAbilityCatalog;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\ConfiguredPolicyAuthManagementAccess;
use Nvl\Auth\Services\FeatureManifest;
use Throwable;

/**
 * Displays effective, secret-free Auth consumer integration state.
 */
final class AuthConfigurationCommand extends Command
{
    /** @var list<class-string> */
    private const ADAPTERS = [AuthManagementAccess::class, SystemMutationAccess::class, AuthSubjectResolver::class, AuthIdentifierResolver::class, AuthenticationEligibility::class, SuccessfulLoginMetadataRecorder::class, PasswordUpdater::class, PasswordPolicy::class, PrincipalAttributeMapper::class, AccountConfirmation::class, PrincipalSessionContainment::class, RbacPrincipalAccess::class, ApiTokenManager::class, ApiTokenAbilityProvider::class, InvitationSubjectResolver::class, InvitationRegistrationMapper::class, SocialIdentityProviderFactory::class, SocialSubjectResolver::class, PasskeyCeremony::class, AuthAuditRecorder::class, AuthAuditContextProvider::class];

    /** @var string */
    protected $signature = 'nvl:auth:configuration
        {--format=text : Output format: text or json}';

    /** @var string */
    protected $description = 'Explain NVL Auth features, ownership, models, adapters, and policy coverage';

    /**
     * Render the effective Auth integration report.
     */
    public function handle(AuthConfiguration $configuration, AuthModelRegistry $models, AuthManagementAbilityCatalog $abilities, FeatureManifest $manifest, Container $container): int
    {
        $format = $this->option('format');
        if (! in_array($format, ['text', 'json'], true)) {
            $this->components->error('The --format option must be text or json.');

            return self::INVALID;
        }
        $report = ['features' => $this->features($configuration, $manifest), 'models' => $this->models($models), 'adapters' => $this->adapters($configuration, $container), 'management' => $this->management($configuration, $abilities, $container), 'configuration_drift' => $this->configurationDrift($container)];
        if ($format === 'json') {
            $this->line((string) json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }
        $this->table(['Feature', 'Enabled'], array_map(static fn (string $feature, array $definition): array => [$feature, $definition['enabled'] ? 'yes' : 'no'], array_keys($report['features']), array_values($report['features'])));
        $this->table(['Boundary', 'Implementation'], array_map(static fn (string $contract, array $adapter): array => [$contract, $adapter['implementation'].($adapter['required'] ? '' : ' (inactive)')], array_keys($report['adapters']), array_values($report['adapters'])));

        return self::SUCCESS;
    }

    /**
     * Build enabled and route-surface state for every feature.
     *
     * @return array<string, array{enabled: bool}>
     */
    private function features(AuthConfiguration $configuration, FeatureManifest $manifest): array
    {
        $features = [];
        foreach ($manifest->definitions() as $definition) {
            $features[$definition->feature->value] = ['enabled' => $configuration->featureEnabled($definition->feature)];
        }

        return $features;
    }

    /**
     * Return validated model class names or a stable invalid marker.
     *
     * @return array<string, string>
     */
    private function models(AuthModelRegistry $models): array
    {
        return ['user' => $this->model($models->userClass(...)), 'role' => $this->model($models->roleClass(...)), 'permission' => $this->model($models->permissionClass(...)), 'personal_access_token' => $this->model($models->personalAccessTokenClass(...))];
    }

    /**
     * Report the resolved public integration boundary.
     *
     * @return array<string, array{implementation: string, required: bool}>
     */
    private function adapters(AuthConfiguration $configuration, Container $container): array
    {
        $adapters = [];
        foreach (self::ADAPTERS as $contract) {
            $resolved = $this->integration($container, $contract);
            $adapters[$contract] = ['implementation' => $resolved === null ? 'unresolvable' : $resolved::class, 'required' => $this->adapterRequired($configuration, $contract)];
        }

        return $adapters;
    }

    /**
     * Determine whether one feature-owned adapter is active.
     *
     * @param  class-string  $contract
     */
    private function adapterRequired(AuthConfiguration $configuration, string $contract): bool
    {
        $feature = match ($contract) {
            PasswordUpdater::class, PasswordPolicy::class => AuthFeature::Password,
            PrincipalAttributeMapper::class, AccountConfirmation::class, PrincipalSessionContainment::class => AuthFeature::PrincipalManagement,
            RbacPrincipalAccess::class => AuthFeature::Rbac,
            ApiTokenManager::class, ApiTokenAbilityProvider::class => AuthFeature::ApiTokens,
            InvitationSubjectResolver::class, InvitationRegistrationMapper::class => AuthFeature::Invitations,
            SocialIdentityProviderFactory::class, SocialSubjectResolver::class => AuthFeature::SocialIdentities,
            PasskeyCeremony::class => AuthFeature::Passkeys,
            AuthAuditRecorder::class, AuthAuditContextProvider::class => AuthFeature::Audit,
            default => AuthFeature::Authentication,
        };

        return $configuration->featureEnabled($feature);
    }

    /**
     * Report coverage for enabled management abilities without exposing values.
     *
     * @return array<string, array{alias: string, configured: bool, policy: string, default_operation: string}>
     */
    private function management(AuthConfiguration $configuration, AuthManagementAbilityCatalog $abilities, Container $container): array
    {
        $access = $this->integration($container, AuthManagementAccess::class);
        $report = [];
        foreach ($abilities->definitions() as $alias => $definition) {
            if (! $configuration->featureEnabled($definition['feature'])) {
                continue;
            }
            $report[$definition['ability']] = ['alias' => $alias, 'configured' => $access instanceof ConfiguredPolicyAuthManagementAccess ? $access->configurationReady($definition['ability']) : $access instanceof AuthManagementAccess, 'policy' => $definition['policy'], 'default_operation' => $definition['operation']];
        }

        return $report;
    }

    /**
     * Include suite-level structural findings when the root package is installed.
     *
     * @return array{available: bool, findings: array<mixed>}
     */
    private function configurationDrift(Container $container): array
    {
        $inspectorClass = 'Nvl\Suite\Services\SuitePackageConfigurationInspector';
        if (! class_exists($inspectorClass) || ! $container->bound($inspectorClass)) {
            return ['available' => false, 'findings' => []];
        }
        try {
            $inspector = $this->integration($container, $inspectorClass);
            if ($inspector === null || ! is_callable([$inspector, 'inspect'])) {
                return ['available' => false, 'findings' => []];
            }
            $findings = call_user_func([$inspector, 'inspect'], ['auth']);

            return ['available' => true, 'findings' => is_array($findings) ? array_values($findings) : []];
        } catch (Throwable) {
            return ['available' => true, 'findings' => []];
        }
    }

    /**
     * Resolve one integration without allowing diagnostics to fail.
     *
     * @param  class-string  $contract
     */
    private function integration(Container $container, string $contract): ?object
    {
        try {
            $resolved = $container->make($contract);

            return is_object($resolved) ? $resolved : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Resolve one model callback without hiding the rest of the registry.
     *
     * @param  callable(): class-string  $resolver
     */
    private function model(callable $resolver): string
    {
        try {
            return $resolver();
        } catch (Throwable) {
            return 'invalid';
        }
    }
}
