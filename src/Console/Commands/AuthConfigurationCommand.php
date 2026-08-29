<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Container\Container;
use Illuminate\Routing\Router;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Contracts\SocialIdentityProvider;
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
    private const ADAPTERS = [
        AuthManagementAccess::class,
        SystemMutationAccess::class,
        AuthSubjectResolver::class,
        AuthIdentifierResolver::class,
        AuthenticationEligibility::class,
        SuccessfulLoginMetadataRecorder::class,
        BrowserSession::class,
        PasswordUpdater::class,
        PrincipalAttributeMapper::class,
        AccountConfirmation::class,
        PrincipalSessionContainment::class,
        RbacPrincipalAccess::class,
        ApiTokenManager::class,
        ApiTokenAbilityProvider::class,
        InvitationSubjectResolver::class,
        InvitationRegistrationMapper::class,
        SocialIdentityProvider::class,
        SocialSubjectResolver::class,
        PasskeyCeremony::class,
        AuthAuditRecorder::class,
        AuthAuditContextProvider::class,
    ];

    /** @var string */
    protected $signature = 'nvl:auth:configuration
        {--format=text : Output format: text or json}';

    /** @var string */
    protected $description = 'Explain NVL Auth features, ownership, models, adapters, and policy coverage';

    /**
     * Render the effective Auth integration report.
     */
    public function handle(
        AuthConfiguration $configuration,
        AuthModelRegistry $models,
        AuthManagementAbilityCatalog $abilities,
        FeatureManifest $manifest,
        Container $container,
        Router $router,
    ): int {
        $format = $this->option('format');

        if (! in_array($format, ['text', 'json'], true)) {
            $this->components->error('The --format option must be text or json.');

            return self::INVALID;
        }

        $report = [
            'features' => $this->features($configuration, $manifest),
            'route_ownership' => $this->routeOwnership($configuration, $router, $manifest),
            'models' => $this->models($models),
            'adapters' => $this->adapters($configuration, $container),
            'management' => $this->management($configuration, $abilities, $container),
            'configuration_drift' => $this->configurationDrift($container),
        ];

        if ($format === 'json') {
            $this->line((string) json_encode(
                $report,
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
            ));

            return self::SUCCESS;
        }

        $this->table(
            ['Feature', 'Enabled', 'Package route surfaces'],
            array_map(
                static fn (string $feature, array $definition): array => [
                    $feature,
                    $definition['enabled'] ? 'yes' : 'no',
                    implode(', ', array_keys(array_filter($definition['package_routes']))),
                ],
                array_keys($report['features']),
                array_values($report['features']),
            ),
        );
        $this->table(
            ['Boundary', 'Implementation'],
            array_map(
                static fn (string $contract, array $adapter): array => [
                    $contract,
                    $adapter['implementation'].($adapter['required'] ? '' : ' (inactive)'),
                ],
                array_keys($report['adapters']),
                array_values($report['adapters']),
            ),
        );

        return self::SUCCESS;
    }

    /**
     * Build enabled and route-surface state for every feature.
     *
     * @return array<string, array{enabled: bool, package_routes: array<string, bool>}>
     */
    private function features(AuthConfiguration $configuration, FeatureManifest $manifest): array
    {
        $features = [];

        foreach ($manifest->definitions() as $definition) {
            $routes = [];

            foreach (array_keys($definition->routeNames) as $surface) {
                $routes[$surface] = $configuration->enabled()
                    && $configuration->boolean('routes.enabled', false)
                    && $configuration->boolean("routes.{$surface}.enabled", false)
                    && $configuration->featureRoutesEnabled($definition->feature, $surface);
            }

            $features[$definition->feature->value] = [
                'enabled' => $configuration->featureEnabled($definition->feature),
                'package_routes' => $routes,
            ];
        }

        return $features;
    }

    /**
     * Report host ownership using counts instead of configuration values.
     *
     * @return array{http: string, delivery: string, host_routes: array<string, array{declared: int, registered: int}>, service_only: list<string>, invalid_entries: int}
     */
    private function routeOwnership(
        AuthConfiguration $configuration,
        Router $router,
        FeatureManifest $manifest,
    ): array {
        $hostRoutes = $configuration->get('ownership.host_routes', []);
        $router->getRoutes()->refreshNameLookups();
        $registered = $router->getRoutes()->getRoutesByName();
        $purposes = $this->routePurposes($manifest);
        $evidence = [];
        $invalidEntries = is_array($hostRoutes) ? 0 : 1;

        if (is_array($hostRoutes)) {
            foreach ($hostRoutes as $purpose => $routes) {
                if (! is_string($purpose)
                    || ! in_array($purpose, $purposes, true)
                    || ! is_array($routes)) {
                    $invalidEntries++;

                    continue;
                }

                $names = array_values(array_filter($routes, 'is_string'));
                $evidence[$purpose] = [
                    'declared' => count($names),
                    'registered' => count(array_filter(
                        $names,
                        static fn (string $name): bool => isset($registered[$name]),
                    )),
                ];
            }
        }

        $serviceOnly = $configuration->get('ownership.service_only', []);

        return [
            'http' => $this->ownership($configuration->get('ownership.http')),
            'delivery' => $this->ownership($configuration->get('ownership.delivery')),
            'host_routes' => $evidence,
            'service_only' => is_array($serviceOnly)
                ? array_values(array_filter(
                    $serviceOnly,
                    static fn (mixed $purpose): bool => is_string($purpose)
                        && in_array($purpose, $purposes, true),
                ))
                : [],
            'invalid_entries' => $invalidEntries + (is_array($serviceOnly)
                ? count($serviceOnly) - count(array_filter(
                    $serviceOnly,
                    static fn (mixed $purpose): bool => is_string($purpose)
                        && in_array($purpose, $purposes, true),
                ))
                : 1),
        ];
    }

    /**
     * Return the closed route-purpose inventory without configured values.
     *
     * @return list<string>
     */
    private function routePurposes(FeatureManifest $manifest): array
    {
        $purposes = [];

        foreach ($manifest->definitions() as $definition) {
            foreach (array_keys($definition->routeNames) as $surface) {
                $purposes[] = "{$definition->feature->value}.{$surface}";
            }
        }

        return $purposes;
    }

    /**
     * Return validated model class names or a stable invalid marker.
     *
     * @return array<string, string>
     */
    private function models(AuthModelRegistry $models): array
    {
        return [
            'user' => $this->model($models->userClass(...)),
            'role' => $this->model($models->roleClass(...)),
            'permission' => $this->model($models->permissionClass(...)),
            'personal_access_token' => $this->model($models->personalAccessTokenClass(...)),
        ];
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
            $adapters[$contract] = [
                'implementation' => $resolved === null ? 'unresolvable' : $resolved::class,
                'required' => $this->adapterRequired($configuration, $contract),
            ];
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
            PasswordUpdater::class => AuthFeature::Password,
            PrincipalAttributeMapper::class,
            AccountConfirmation::class,
            PrincipalSessionContainment::class => AuthFeature::PrincipalManagement,
            RbacPrincipalAccess::class => AuthFeature::Rbac,
            ApiTokenManager::class,
            ApiTokenAbilityProvider::class => AuthFeature::ApiTokens,
            InvitationSubjectResolver::class,
            InvitationRegistrationMapper::class => AuthFeature::Invitations,
            SocialIdentityProvider::class,
            SocialSubjectResolver::class => AuthFeature::SocialIdentities,
            PasskeyCeremony::class => AuthFeature::Passkeys,
            AuthAuditRecorder::class,
            AuthAuditContextProvider::class => AuthFeature::Audit,
            BrowserSession::class => AuthFeature::Sessions,
            default => AuthFeature::Authentication,
        };

        return $configuration->featureEnabled($feature);
    }

    /**
     * Report coverage for enabled management abilities without exposing values.
     *
     * @return array<string, array{alias: string, configured: bool, policy: string, default_operation: string}>
     */
    private function management(
        AuthConfiguration $configuration,
        AuthManagementAbilityCatalog $abilities,
        Container $container,
    ): array {
        $access = $this->integration($container, AuthManagementAccess::class);

        $report = [];

        foreach ($abilities->definitions() as $alias => $definition) {
            if (! $configuration->featureEnabled($definition['feature'])) {
                continue;
            }

            $report[$definition['ability']] = [
                'alias' => $alias,
                'configured' => $access instanceof ConfiguredPolicyAuthManagementAccess
                    ? $access->configurationReady($definition['ability'])
                    : $access instanceof AuthManagementAccess,
                'policy' => $definition['policy'],
                'default_operation' => $definition['operation'],
            ];
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
        $inspectorClass = 'Nvl\\Suite\\Services\\SuitePackageConfigurationInspector';

        if (! class_exists($inspectorClass) || ! $container->bound($inspectorClass)) {
            return ['available' => false, 'findings' => []];
        }

        try {
            $inspector = $this->integration($container, $inspectorClass);

            if ($inspector === null || ! is_callable([$inspector, 'inspect'])) {
                return ['available' => false, 'findings' => []];
            }

            $findings = call_user_func([$inspector, 'inspect'], ['auth']);

            return [
                'available' => true,
                'findings' => is_array($findings) ? array_values($findings) : [],
            ];
        } catch (Throwable) {
            return ['available' => true, 'findings' => []];
        }
    }

    /**
     * Normalize an ownership marker without returning arbitrary scalar data.
     */
    private function ownership(mixed $value): string
    {
        return in_array($value, ['host', 'package'], true) ? $value : 'invalid';
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
