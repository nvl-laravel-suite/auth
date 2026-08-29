<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Builder;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Adapters\ApiTokens\SanctumApiTokenManager;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthManagementAbilityCatalog;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthSchemaManager;
use Nvl\Auth\Services\ConfiguredApiTokenAbilityProvider;
use Nvl\Auth\Services\ConfiguredPolicyAuthManagementAccess;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;
use Nvl\Auth\Services\InvitationDeliveryMetadataPolicy;
use Nvl\Auth\Services\LaravelGateAuthManagementAccess;
use Nvl\Auth\Services\SocialProviderConfiguration;
use Nvl\Auth\Services\UnavailableApiTokenManager;
use Nvl\Auth\Services\UnavailableAuthSubjectResolver;
use Nvl\Auth\Services\UnavailableInvitationSubjectResolver;
use Nvl\Auth\Services\UnavailableSocialIdentityProvider;
use Nvl\Auth\Services\UnavailableSocialSubjectResolver;
use Nvl\Auth\ValueObjects\FeatureDefinition;
use ReflectionMethod;
use ReflectionNamedType;
use Throwable;

/**
 * Validates schema ownership and enabled integration readiness.
 */
final class AuthDoctorCommand extends Command
{
    private const PIPELINES = [
        'login',
        'logout',
        'password_reset_requested',
        'password_reset',
        'invitation_issued',
        'invitation_accepted',
        'client_started',
        'api_token_issued',
    ];

    private const CONFIGURABLE_TABLES = [
        AuthTables::Users => 'users',
        AuthTables::Permissions => 'permissions',
        AuthTables::Roles => 'roles',
        AuthTables::ModelHasPermissions => 'model_has_permissions',
        AuthTables::ModelHasRoles => 'model_has_roles',
        AuthTables::RoleHasPermissions => 'role_has_permissions',
        AuthTables::PersonalAccessTokens => 'personal_access_tokens',
        AuthTables::PasswordResetTokens => 'password_reset_tokens',
    ];

    private const TABLE_COLUMNS = [
        AuthTables::Users => ['id', 'name', 'email', 'email_verified_at', 'password', 'is_active', 'locale', 'timezone', 'profile', 'preferences', 'last_login_at', 'last_login_ip', 'locked_until', 'remember_token', 'created_at', 'updated_at', 'deleted_at'],
        AuthTables::Permissions => ['id', 'name', 'guard_name', 'display_name', 'description', 'group', 'is_system', 'metadata', 'created_at', 'updated_at'],
        AuthTables::Roles => ['id', 'name', 'guard_name', 'display_name', 'description', 'parent_id', 'priority', 'is_system', 'metadata', 'created_at', 'updated_at'],
        AuthTables::ModelHasPermissions => ['permission_id', 'model_type', 'model_id'],
        AuthTables::ModelHasRoles => ['role_id', 'model_type', 'model_id'],
        AuthTables::RoleHasPermissions => ['permission_id', 'role_id'],
        AuthTables::PersonalAccessTokens => ['id', 'tokenable_type', 'tokenable_id', 'name', 'token', 'abilities', 'last_used_at', 'expires_at', 'created_at', 'updated_at'],
        AuthTables::PasswordResetTokens => ['email', 'token', 'created_at'],
        AuthTables::Clients => ['id', 'name', 'surface', 'base_url', 'return_paths', 'allowed_origins', 'allowed_flows', 'metadata', 'is_active', 'last_used_at', 'created_at', 'updated_at'],
        AuthTables::ClientSessions => ['id', 'client_id', 'subject_type', 'subject_id', 'session_id_hash', 'ip_address', 'user_agent', 'metadata', 'authenticated_at', 'last_seen_at', 'ended_at', 'end_reason', 'created_at', 'updated_at'],
        AuthTables::Invitations => ['id', 'token_hash', 'active_key', 'recipient', 'recipient_hash', 'context_hash', 'type', 'purpose', 'inviter_type', 'inviter_id', 'accepted_by_type', 'accepted_by_id', 'roles', 'permissions', 'metadata', 'resend_count', 'current_delivery_message_id', 'delivery_status', 'delivery_attempted_at', 'delivered_at', 'delivery_failed_at', 'delivery_failure_code', 'last_sent_at', 'expires_at', 'accepted_at', 'revoked_at', 'created_at', 'updated_at'],
        AuthTables::Challenges => ['id', 'type', 'purpose', 'subject_type', 'subject_id', 'recipient_hash', 'secret_hash', 'secondary_secret_hash', 'active_key', 'payload', 'attempts', 'max_attempts', 'expires_at', 'consumed_at', 'revoked_at', 'created_at', 'updated_at'],
        AuthTables::TotpCredentials => ['id', 'subject_type', 'subject_id', 'name', 'secret', 'algorithm', 'digits', 'period', 'allowed_drift', 'last_accepted_timestep', 'confirmed_at', 'last_used_at', 'revoked_at', 'created_at', 'updated_at'],
        AuthTables::Passkeys => ['id', 'subject_type', 'subject_id', 'name', 'credential_id', 'credential_id_hash', 'public_key', 'user_handle', 'signature_counter', 'transports', 'backup_eligible', 'backed_up', 'last_used_at', 'revoked_at', 'created_at', 'updated_at'],
        AuthTables::RecoveryCodes => ['id', 'batch_id', 'subject_type', 'subject_id', 'code_hash', 'used_at', 'revoked_at', 'created_at', 'updated_at'],
        AuthTables::SocialIdentities => ['id', 'subject_type', 'subject_id', 'provider', 'provider_user_id', 'provider_user_id_hash', 'email', 'profile', 'last_used_at', 'revoked_at', 'created_at', 'updated_at'],
        AuthTables::Audits => ['id', 'action', 'outcome', 'subject_type', 'subject_id', 'actor_type', 'actor_id', 'client_id', 'ip_address', 'user_agent', 'request_id', 'metadata', 'created_at', 'updated_at'],
    ];

    /** @var array<string, array<string, bool>> */
    private const TABLE_INDEXES = [
        AuthTables::Invitations => [
            'nvl_auth_invitations_context_hash_index' => false,
            'nvl_auth_invitations_delivery_status_index' => false,
        ],
        AuthTables::Challenges => [
            'nvl_auth_challenges_secondary_secret_hash_unique' => true,
        ],
    ];

    private const LEGACY_TABLES = [
        'auth_clients',
        'auth_client_sessions',
        'auth_invitations',
        'auth_challenges',
        'auth_totp_credentials',
        'auth_passkeys',
        'auth_recovery_codes',
        'auth_social_identities',
        'auth_audits',
        'auth_principals',
        'auth_contacts',
        'auth_flows',
        'auth_sessions',
        'auth_api_tokens',
        'auth_deliveries',
        'auth_delivery_attempts',
        'auth_delivery_payloads',
        'auth_security_events',
        'auth_security_event_contexts',
        'auth_outbox_messages',
        'auth_maintenance_checkpoints',
        'auth_recovery_password_updates',
    ];

    /** @var string */
    protected $signature = 'nvl:auth:doctor
        {--strict : Fail for configured integrations owned by disabled features}
        {--format=text : Output format: text or json}';

    /** @var string */
    protected $description = 'Validate NVL Auth schema and enabled feature readiness';

    /**
     * Execute package readiness diagnostics.
     */
    public function handle(
        AuthConfiguration $configuration,
        FeatureManifest $manifest,
        FeatureGate $features,
        Router $router,
        Container $container,
        AuthSchemaManager $schemaManager,
        PrincipalAttributeMapper $principalAttributes,
        ?InvitationDeliveryMetadataPolicy $deliveryMetadata = null,
    ): int {
        $format = $this->option('format');

        if (! is_string($format) || ! in_array($format, ['text', 'json'], true)) {
            $this->components->error('The --format option must be text or json.');

            return self::INVALID;
        }

        $checks = [];
        $strict = (bool) $this->option('strict');
        $migrationDuplicates = config('nvl-auth.migrations.enabled') === true
            ? $this->publishedMigrationDuplicates(dirname(__DIR__, 3).'/database/migrations')
            : [];
        $checks[] = $this->check(
            'migrations.ownership',
            $migrationDuplicates === [],
            sprintf(
                'Automatic vendor migration loading overlaps published host migration(s): %s. Disable nvl-auth.migrations.enabled before running host-owned copies.',
                implode(', ', $migrationDuplicates),
            ),
            'warning',
        );
        $connection = $configuration->get('connection');
        $schema = Schema::connection(is_string($connection) && $connection !== '' ? $connection : null);

        $requiredTables = $schemaManager->requiredTables();

        foreach (self::TABLE_COLUMNS as $defaultTable => $columns) {
            $table = $this->configuredTable($configuration, $defaultTable);

            if (! in_array($table, $requiredTables, true)) {
                continue;
            }

            if ($defaultTable === AuthTables::Users) {
                $columns = array_map(
                    $principalAttributes->column(...),
                    PrincipalAttribute::cases(),
                );
            }

            $exists = $schema->hasTable($table);
            $checks[] = $this->check("schema.{$table}", $exists, "Required table [{$table}] is missing.");
            $checks[] = $this->check(
                "schema.{$table}.columns",
                $exists && $schema->hasColumns($table, $columns),
                "Required table [{$table}] is partial or outdated.",
            );

            foreach (self::TABLE_INDEXES[$defaultTable] ?? [] as $index => $unique) {
                $checks[] = $this->check(
                    "schema.{$table}.index.{$index}",
                    $exists && $this->indexReady($schema, $table, $index, $unique),
                    "Required table [{$table}] is missing index [{$index}].",
                );
            }
        }

        foreach (self::LEGACY_TABLES as $table) {
            if ($schema->hasTable($table)) {
                $checks[] = $this->check("legacy.{$table}", false, "Legacy overreaching table [{$table}] still exists.");
            }
        }

        $appKey = config('app.key');
        $checks[] = $this->check('security.app_key', is_string($appKey) && $appKey !== '', 'APP_KEY is required for hashing and encrypted casts.');
        $checks[] = $this->check(
            'configuration.pipelines',
            $this->pipelinesReady($configuration, $container),
            'Auth pipelines contain an unknown pipeline or invalid stage.',
        );
        $checks[] = $this->check(
            'configuration.models',
            $this->ownedModelsReady($container),
            'Configured User, Role, Permission, or PersonalAccessToken models do not extend their package model.',
        );
        $checks = [
            ...$checks,
            ...$this->ownershipChecks($configuration, $manifest, $router),
        ];
        $principalTable = $this->configuredTable($configuration, AuthTables::Users);
        $attributeCollisions = $configuration->featureEnabled(AuthFeature::PrincipalManagement)
            && $schema->hasTable($principalTable)
                ? $this->principalAttributeCollisions($container, $schema, $principalTable)
                : [];
        $checks[] = $this->check(
            'configuration.principal_attributes',
            $attributeCollisions === [],
            sprintf(
                'Physical principal columns collide with Eloquent relationships: %s.',
                implode(', ', $attributeCollisions),
            ),
        );

        if ($configuration->boolean('features.principal_management.settings.use_as_auth_model', true)) {
            $checks[] = $this->check(
                'configuration.auth_provider',
                $this->authProviderReady($configuration, $container),
                'The configured guard provider is not using the selected package User model.',
            );
        }

        if ((bool) $this->option('strict')) {
            foreach ($this->dormantIntegrations($configuration) as $path) {
                $checks[] = $this->check(
                    "dormant.{$path}",
                    false,
                    "Disabled features must not retain integration configuration [{$path}] in strict mode.",
                );
            }
        }

        if ($configuration->featureEnabled(AuthFeature::Password)) {
            $checks[] = $this->check(
                'contract.password_updater',
                $this->integration($container, PasswordUpdater::class) instanceof PasswordUpdater,
                'Password operations require a valid password updater.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::Authentication)) {
            $checks[] = $this->check(
                'contract.authentication_eligibility',
                $this->integration($container, AuthenticationEligibility::class) instanceof AuthenticationEligibility,
                'Authentication operations require a valid eligibility policy.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::PrincipalManagement)) {
            $checks[] = $this->check(
                'contract.account_confirmation',
                $this->integration($container, AccountConfirmation::class) instanceof AccountConfirmation,
                'Sensitive self-service mutations require a valid account confirmation policy.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::Sessions)) {
            $checks[] = $this->check(
                'contract.browser_session',
                $this->integration($container, BrowserSession::class) instanceof BrowserSession,
                'Session operations require a valid browser-session adapter.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::Audit)) {
            $checks[] = $this->check(
                'contract.audit_context',
                $this->integration($container, AuthAuditContextProvider::class) instanceof AuthAuditContextProvider,
                'Audit recording requires a valid context provider.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::MagicLinks)) {
            $checks[] = $this->check(
                'contract.identifier_resolver',
                $this->integration($container, AuthIdentifierResolver::class) instanceof AuthIdentifierResolver,
                'Magic-link authentication requires a valid identifier resolver.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::EmailVerification)) {
            $checks[] = $this->check(
                'contract.email_verification_subject_resolver',
                $this->integration($container, AuthSubjectResolver::class) instanceof AuthSubjectResolver,
                'Public email verification requires a valid subject resolver.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::Invitations)) {
            $checks[] = $this->check(
                'configuration.invitations.delivery_metadata_keys',
                ($deliveryMetadata ?? new InvitationDeliveryMetadataPolicy(
                    $configuration,
                ))->configurationIsValid(),
                'Invitation delivery metadata keys must be a bounded safe allowlist.',
            );
            $checks[] = $this->check(
                'contract.invitation_registration_mapper',
                $this->integration($container, InvitationRegistrationMapper::class) instanceof InvitationRegistrationMapper,
                'Invitation registration requires a valid principal attribute mapper.',
            );
        }

        foreach ($manifest->definitions() as $definition) {
            if (! $configuration->featureEnabled($definition->feature)) {
                continue;
            }

            foreach ($definition->dependencies as $dependency) {
                $checks[] = $this->check(
                    "dependency.{$definition->feature->value}.{$dependency->value}",
                    $configuration->featureEnabled($dependency),
                    "Feature [{$definition->feature->value}] requires [{$dependency->value}].",
                );
            }

            foreach ($definition->routeDependencies as $surface => $dependencies) {
                if (! $this->routeSurfaceConfigured($configuration, $definition->feature, $surface)) {
                    continue;
                }

                foreach ($dependencies as $dependency) {
                    $checks[] = $this->check(
                        "route_dependency.{$definition->feature->value}.{$surface}.{$dependency->value}",
                        $configuration->featureEnabled($dependency),
                        "Feature [{$definition->feature->value}] {$surface} routes require [{$dependency->value}].",
                    );
                }
            }
        }

        if ($configuration->featureEnabled(AuthFeature::ApiTokens)) {
            $apiTokens = $this->integration($container, ApiTokenManager::class);
            $abilityProvider = $this->integration($container, ApiTokenAbilityProvider::class);
            $checks[] = $this->check('adapter.api_tokens', $apiTokens !== null && ! $apiTokens instanceof UnavailableApiTokenManager, 'API tokens require a configured provider adapter.');
            $checks[] = $this->check(
                'contract.api_token_abilities',
                $this->apiTokenAbilitiesReady($configuration, $abilityProvider),
                'API tokens require a non-empty static ability catalog or a custom ability provider.',
            );

            if ($apiTokens instanceof SanctumApiTokenManager) {
                $namespace = $configuration->get('features.api_tokens.settings.namespace');
                $checks[] = $this->check(
                    'configuration.api_token_namespace',
                    is_string($namespace)
                        && preg_match('/\A[a-z0-9][a-z0-9_.-]{0,39}\z/', $namespace) === 1,
                    'The Sanctum adapter requires a valid package token namespace.',
                );
                $checks[] = $this->check(
                    'schema.personal_access_tokens',
                    $this->sanctumStorageReady(),
                    'The Sanctum adapter requires package-owned nvl_auth_personal_access_tokens storage.',
                );
            }
        }

        if ($configuration->featureEnabled(AuthFeature::SocialIdentities)) {
            $socialIdentities = $this->integration($container, SocialIdentityProvider::class);
            $socialSubjects = $this->integration($container, SocialSubjectResolver::class);
            $checks[] = $this->check('adapter.social_identities', $socialIdentities !== null && ! $socialIdentities instanceof UnavailableSocialIdentityProvider, 'Social identities require a configured acquisition adapter.');
            $checks[] = $this->check('contract.social_subject_resolver', $socialSubjects !== null && ! $socialSubjects instanceof UnavailableSocialSubjectResolver, 'Social login requires a configured principal resolver.');
            $checks[] = $this->check(
                'social.providers',
                $this->hasConfiguredSocialProvider($configuration, $container),
                'Social identities require at least one configured provider.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::Passkeys)) {
            $passkeys = $this->integration($container, PasskeyCeremony::class);
            $subjects = $this->integration($container, AuthSubjectResolver::class);
            $checks[] = $this->check(
                'adapter.passkeys',
                $passkeys instanceof PasskeyCeremony,
                'The configured or built-in passkey ceremony implementation could not be resolved.',
            );
            $checks[] = $this->check('contract.auth_subject_resolver', $subjects !== null && ! $subjects instanceof UnavailableAuthSubjectResolver, 'Passwordless login requires a configured principal resolver.');
            $relyingPartyId = $configuration->get('features.passkeys.settings.relying_party_id');
            $origins = $configuration->get('features.passkeys.settings.origins', []);
            $checks[] = $this->check(
                'passkeys.relying_party_id',
                $this->validRelyingPartyId($relyingPartyId),
                'Passkeys require a valid hostname-only relying-party ID.',
            );
            $checks[] = $this->check(
                'passkeys.origins',
                $this->validOrigins($origins, $relyingPartyId),
                'Passkeys require HTTPS origins matching the relying-party ID.',
            );
            $maximumCredentials = $configuration->get('features.passkeys.settings.max_credentials_per_subject');
            $checks[] = $this->check(
                'passkeys.max_credentials_per_subject',
                is_int($maximumCredentials) && $maximumCredentials >= 1 && $maximumCredentials <= 100,
                'Passkeys require a credential limit between 1 and 100.',
            );
            $checks[] = $this->check(
                'passkeys.require_user_verification',
                is_bool($configuration->get('features.passkeys.settings.require_user_verification')),
                'Passkey user-verification policy must be boolean.',
            );
            $checks[] = $this->check(
                'passkeys.relying_party_name',
                $this->boundedString($configuration->get('features.passkeys.settings.relying_party_name'), 255),
                'Passkeys require a relying-party name of at most 255 characters.',
            );
            $checks[] = $this->check(
                'passkeys.allow_subdomains',
                is_bool($configuration->get('features.passkeys.settings.allow_subdomains')),
                'Passkey subdomain policy must be boolean.',
            );
            $timeout = $configuration->get('features.passkeys.settings.timeout_ms');
            $ttl = $configuration->get('features.passkeys.settings.ceremony_ttl_seconds');
            $checks[] = $this->check(
                'passkeys.timeout_ms',
                is_int($timeout) && $timeout >= 1_000 && $timeout <= 600_000,
                'Passkey browser timeout must be between 1,000 and 600,000 milliseconds.',
            );
            $checks[] = $this->check(
                'passkeys.ceremony_ttl_seconds',
                is_int($ttl)
                    && $ttl >= 60
                    && $ttl <= 900
                    && is_int($timeout)
                    && $ttl * 1_000 >= $timeout,
                'Passkey ceremony TTL must be 60 to 900 seconds and cover the browser timeout.',
            );
            $checks[] = $this->check(
                'passkeys.resident_key',
                in_array(
                    $configuration->get('features.passkeys.settings.resident_key'),
                    ['required', 'preferred', 'discouraged'],
                    true,
                ),
                'Passkey resident-key policy must be required, preferred, or discouraged.',
            );
            $checks[] = $this->check(
                'passkeys.username_attribute',
                $this->boundedString($configuration->get('features.passkeys.settings.username_attribute'), 255),
                'Passkeys require a configured principal username attribute.',
            );
            $checks[] = $this->check(
                'passkeys.display_name_attribute',
                $this->boundedString($configuration->get('features.passkeys.settings.display_name_attribute'), 255),
                'Passkeys require a configured principal display-name attribute.',
            );
            $checks[] = $this->check(
                'passkeys.user_handle_key',
                $this->validPasskeyUserHandleKey($configuration, $container),
                'Passkeys require at least 32 bytes of user-handle key material or Laravel APP_KEY.',
            );
        }

        if ($configuration->featureEnabled(AuthFeature::Invitations)
            && $this->routeSurfaceConfigured($configuration, AuthFeature::Invitations, 'public')) {
            $invitationSubjects = $this->integration($container, InvitationSubjectResolver::class);
            $checks[] = $this->check('contract.invitation_subject_resolver', $invitationSubjects !== null && ! $invitationSubjects instanceof UnavailableInvitationSubjectResolver, 'Public invitations require a configured principal resolver.');
        }

        if ($configuration->featureEnabled(AuthFeature::Rbac)) {
            $spatieTables = $this->spatieTables();
            $checks[] = $this->check(
                'configuration.spatie_tables',
                count($spatieTables) === 5,
                'RBAC requires the complete Spatie Permission table configuration.',
            );

            foreach ($spatieTables as $table) {
                $checks[] = $this->check(
                    "schema.spatie.{$table}",
                    $schema->hasTable($table),
                    "RBAC requires Spatie Permission table [{$table}].",
                );
            }
        }

        $managementAccess = $this->integration($container, AuthManagementAccess::class);

        if ($managementAccess instanceof ConfiguredPolicyAuthManagementAccess) {
            $checks[] = $this->check(
                'configuration.management',
                $this->managementConfigurationReady(
                    $configuration,
                    new AuthManagementAbilityCatalog,
                ),
                'Management policy mappings contain unknown aliases, invalid operations, or invalid model classes.',
            );
        }

        foreach ($this->managementAbilities($configuration, $manifest) as $ability) {
            $checks[] = $this->check(
                "authorization.{$ability}",
                $this->managementAbilityReady($configuration, $container, $ability, $managementAccess),
                $managementAccess instanceof ConfiguredPolicyAuthManagementAccess
                    ? "Management authorization has no resolvable policy decision for [{$ability}]."
                    : "Management routes require package RBAC or Laravel Gate authorization for [{$ability}].",
            );
        }

        $expectedRoutes = $this->expectedRoutes($configuration, $manifest, $features);
        $actualRoutes = array_values(array_filter(
            array_keys($router->getRoutes()->getRoutesByName()),
            static fn (string $name): bool => str_starts_with($name, 'nvl.auth.'),
        ));
        sort($expectedRoutes);
        sort($actualRoutes);
        $checks[] = $this->check(
            'routes.inventory',
            $expectedRoutes === $actualRoutes,
            'Auth route inventory differs from configuration; rebuild route and configuration caches.',
        );

        $failed = count(array_filter(
            $checks,
            static fn (array $check): bool => ! $check['passed']
                && ($check['severity'] === 'error' || $strict),
        ));

        if ($format === 'json') {
            $this->line((string) json_encode(['ready' => $failed === 0, 'checks' => $checks], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        } else {
            $this->table(['Check', 'Severity', 'Result', 'Message'], array_map(static fn (array $check): array => [
                $check['name'],
                $check['severity'],
                $check['passed'] ? 'PASS' : 'FAIL',
                $check['message'],
            ], $checks));
        }

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Inspect Sanctum's configured token model without making it a core dependency.
     */
    private function sanctumStorageReady(): bool
    {
        $sanctum = 'Laravel\\Sanctum\\Sanctum';

        if (! class_exists($sanctum)) {
            return false;
        }

        try {
            $modelClass = (new ReflectionMethod($sanctum, 'personalAccessTokenModel'))->invoke(null);

            if (! is_string($modelClass) || ! class_exists($modelClass)) {
                return false;
            }

            $model = new $modelClass;

            return $model instanceof Model
                && Schema::connection($model->getConnectionName())->hasTable($model->getTable());
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Build one diagnostic check.
     *
     * @return array{name: string, severity: string, passed: bool, message: string}
     */
    private function check(
        string $name,
        bool $passed,
        string $failure,
        string $severity = 'error',
    ): array {
        return [
            'name' => $name,
            'severity' => $severity,
            'passed' => $passed,
            'message' => $passed ? 'Ready.' : $failure,
        ];
    }

    /**
     * Find host migrations whose timestamp-independent names match package migrations.
     *
     * @return list<string>
     */
    private function publishedMigrationDuplicates(string $packagePath): array
    {
        $packageMigrations = glob($packagePath.'/*.php') ?: [];
        $hostMigrations = glob(database_path('migrations/*.php')) ?: [];
        $packageNames = array_map($this->migrationName(...), $packageMigrations);
        $duplicates = [];

        foreach ($hostMigrations as $migration) {
            $name = $this->migrationName($migration);

            if (in_array($name, $packageNames, true)) {
                $duplicates[] = $name;
            }
        }

        sort($duplicates);

        return array_values(array_unique($duplicates));
    }

    /**
     * Remove Laravel's timestamp prefix from a migration filename.
     */
    private function migrationName(string $path): string
    {
        return (string) preg_replace(
            '/^\d{4}_\d{2}_\d{2}_\d{6}_/',
            '',
            pathinfo($path, PATHINFO_FILENAME),
        );
    }

    /** Resolve a configurable identity/provider table name. */
    private function configuredTable(AuthConfiguration $configuration, string $default): string
    {
        $key = self::CONFIGURABLE_TABLES[$default] ?? null;

        if ($key === null) {
            return $default;
        }

        $configured = $configuration->get("tables.{$key}", $default);

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : $default;
    }

    /** Determine whether every configured package model has a valid base type. */
    private function ownedModelsReady(Container $container): bool
    {
        try {
            $models = $container->make(AuthModelRegistry::class);

            return class_exists($models->userClass())
                && class_exists($models->roleClass())
                && class_exists($models->permissionClass())
                && class_exists($models->personalAccessTokenClass());
        } catch (Throwable) {
            return false;
        }
    }

    /** Ensure Laravel's configured guard provider resolves the selected User. */
    private function authProviderReady(AuthConfiguration $configuration, Container $container): bool
    {
        try {
            $models = $container->make(AuthModelRegistry::class);
            $guard = $configuration->get('guard', 'web');
            $provider = is_string($guard) ? config("auth.guards.{$guard}.provider") : null;
            $configured = is_string($provider) ? config("auth.providers.{$provider}.model") : null;

            return is_string($configured)
                && $configured === $models->userClass();
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Resolve an optional integration without crashing diagnostics.
     *
     * @param  class-string  $contract
     */
    private function integration(Container $container, string $contract): ?object
    {
        try {
            $integration = $container->make($contract);

            return is_object($integration) ? $integration : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Determine whether the closed pipeline tree contains resolvable stages.
     */
    private function pipelinesReady(AuthConfiguration $configuration, Container $container): bool
    {
        $pipelines = $configuration->get('pipelines', []);

        if (! is_array($pipelines) || array_keys($pipelines) !== self::PIPELINES) {
            return false;
        }

        foreach ($pipelines as $stages) {
            if (! is_array($stages)) {
                return false;
            }

            foreach ($stages as $stage) {
                if (! is_string($stage) || ! is_a($stage, AuthPipelineStage::class, true)) {
                    return false;
                }

                try {
                    if (! $container->make($stage) instanceof AuthPipelineStage) {
                        return false;
                    }
                } catch (Throwable) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Return non-empty service configuration owned by disabled features.
     *
     * @return list<string>
     */
    private function dormantIntegrations(AuthConfiguration $configuration): array
    {
        $paths = [];

        foreach (AuthFeature::cases() as $feature) {
            if ($configuration->featureEnabled($feature)) {
                continue;
            }

            $services = $configuration->get("features.{$feature->value}.services", []);

            if (! is_array($services)) {
                $paths[] = "features.{$feature->value}.services";

                continue;
            }

            foreach ($services as $service => $value) {
                if ($value === null || $value === '' || $value === []) {
                    continue;
                }

                $paths[] = "features.{$feature->value}.services.{$service}";
            }
        }

        return $paths;
    }

    /**
     * Return abilities owned by enabled management features.
     *
     * @return list<string>
     */
    private function managementAbilities(
        AuthConfiguration $configuration,
        FeatureManifest $manifest,
    ): array {
        $abilities = [];

        foreach ($manifest->definitions() as $definition) {
            if (! $configuration->featureEnabled($definition->feature)) {
                continue;
            }

            foreach ($definition->managementAbilities as $ability) {
                $abilities[$ability] = true;
            }
        }

        return array_keys($abilities);
    }

    /**
     * Determine whether package RBAC or the configured Gate owns an ability.
     */
    private function managementAbilityReady(
        AuthConfiguration $configuration,
        Container $container,
        string $ability,
        ?object $access = null,
    ): bool {
        $access ??= $this->integration($container, AuthManagementAccess::class);

        if (! $access instanceof AuthManagementAccess) {
            return false;
        }

        if ($access instanceof ConfiguredPolicyAuthManagementAccess) {
            return $access->configurationReady($ability);
        }

        if (! $access instanceof LaravelGateAuthManagementAccess) {
            return true;
        }

        $gate = $this->integration($container, GateContract::class);

        if ($gate instanceof GateContract && $gate->has($ability)) {
            return true;
        }

        $superAdminRole = $configuration->get('features.rbac.settings.super_admin_role');

        return $configuration->featureEnabled(AuthFeature::Rbac)
            && is_string($superAdminRole)
            && trim($superAdminRole) !== '';
    }

    /**
     * Validate every configured alias, host operation, and policy model.
     */
    private function managementConfigurationReady(
        AuthConfiguration $configuration,
        AuthManagementAbilityCatalog $catalog,
    ): bool {
        $abilities = $configuration->get('management.abilities', []);
        $policyModels = $configuration->get('management.policy_models', []);

        if (! is_array($abilities) || ! is_array($policyModels)) {
            return false;
        }

        $definitions = $catalog->definitions();
        $policyDefaults = [];

        foreach ($definitions as $definition) {
            $policyDefaults[$definition['policy']] = $definition['default_model'];
        }

        foreach ($abilities as $alias => $operation) {
            if (! is_string($alias)
                || ! array_key_exists($alias, $definitions)
                || ! is_string($operation)
                || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,119}\z/', $operation) !== 1) {
                return false;
            }
        }

        foreach ($policyModels as $policy => $model) {
            $defaultModel = is_string($policy) ? ($policyDefaults[$policy] ?? null) : null;

            if (! is_string($policy)
                || ! is_string($defaultModel)
                || ! is_string($model)
                || ! is_a($model, Model::class, true)
                || ! is_a($model, $defaultModel, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate explicit HTTP and delivery ownership declarations.
     *
     * @return list<array{name: string, severity: string, passed: bool, message: string}>
     */
    private function ownershipChecks(
        AuthConfiguration $configuration,
        FeatureManifest $manifest,
        Router $router,
    ): array {
        $checks = [
            $this->check(
                'ownership.http',
                in_array($configuration->get('ownership.http'), ['host', 'package'], true),
                'Auth HTTP ownership must be host or package.',
            ),
            $this->check(
                'ownership.delivery',
                in_array($configuration->get('ownership.delivery'), ['host', 'package'], true),
                'Auth delivery ownership must be host or package.',
            ),
        ];
        $hostRoutes = $configuration->get('ownership.host_routes', []);
        $serviceOnly = $configuration->get('ownership.service_only', []);

        if (! is_array($hostRoutes) || ! is_array($serviceOnly)) {
            $checks[] = $this->check(
                'ownership.host_routes',
                false,
                'Auth host route evidence and service-only flows must be arrays.',
            );

            return $checks;
        }

        $configuredServiceOnlyCount = count($serviceOnly);
        $serviceOnly = array_values(array_filter($serviceOnly, 'is_string'));
        $serviceOnlyReady = count($serviceOnly) === $configuredServiceOnlyCount;

        foreach ($serviceOnly as $purpose) {
            $serviceOnlyReady = $serviceOnlyReady
                && $this->hostFlowDefinition($manifest, $purpose) !== null;
        }

        $checks[] = $this->check(
            'ownership.service_only',
            $serviceOnlyReady,
            'Auth service-only flows must use known feature surfaces.',
        );
        $router->getRoutes()->refreshNameLookups();
        $registered = $router->getRoutes()->getRoutesByName();
        $routeEvidence = [];

        foreach ($hostRoutes as $purpose => $routes) {
            $definition = is_string($purpose)
                ? $this->hostFlowDefinition($manifest, $purpose)
                : null;
            $routeNames = is_array($routes)
                ? array_values(array_filter(
                    $routes,
                    static fn (mixed $route): bool => is_string($route) && trim($route) !== '',
                ))
                : [];
            $routeEvidenceReady = is_array($routes)
                && array_is_list($routes)
                && count($routeNames) === count($routes);
            $hasEvidence = $routeNames !== [] && count(array_filter(
                $routeNames,
                static fn (string $route): bool => isset($registered[$route]),
            )) === count($routeNames);

            $checks[] = $this->check(
                'ownership.host_routes.'.(is_string($purpose) ? $purpose : 'invalid'),
                $definition !== null && $routeEvidenceReady,
                'Auth host route evidence must contain known feature surfaces and non-empty route-name lists.',
            );

            if ($definition === null || ! $routeEvidenceReady) {
                continue;
            }

            $routeEvidence[$purpose] = $hasEvidence;

            $packageOwnsFlow = $this->routeSurfaceConfigured(
                $configuration,
                $definition['feature'],
                $definition['surface'],
            );
            $checks[] = $this->check(
                "ownership.host_routes.{$purpose}.conflict",
                ! ($packageOwnsFlow && $hasEvidence),
                "Auth flow [{$purpose}] is owned by both package and host routes.",
            );
        }

        if ($configuration->get('ownership.http') === 'host') {
            foreach ($manifest->definitions() as $definition) {
                if (! $configuration->featureEnabled($definition->feature)) {
                    continue;
                }

                foreach (array_keys($definition->routeNames) as $surface) {
                    $purpose = "{$definition->feature->value}.{$surface}";

                    if (in_array($purpose, $serviceOnly, true)) {
                        continue;
                    }

                    $checks[] = $this->check(
                        "ownership.host_routes.{$purpose}.evidence",
                        $routeEvidence[$purpose] ?? false,
                        "Host-owned Auth flow [{$purpose}] has no registered route evidence.",
                        'warning',
                    );
                }
            }
        }

        return $checks;
    }

    /**
     * Resolve one declared host flow against the closed feature manifest.
     *
     * @return array{feature: AuthFeature, surface: string}|null
     */
    private function hostFlowDefinition(FeatureManifest $manifest, string $purpose): ?array
    {
        [$featureName, $surface] = array_pad(explode('.', $purpose, 2), 2, null);
        $feature = is_string($featureName) ? AuthFeature::tryFrom($featureName) : null;

        if ($feature === null || ! is_string($surface)) {
            return null;
        }

        $definition = $manifest->definition($feature);

        if (! array_key_exists($surface, $definition->routeNames)) {
            return null;
        }

        return ['feature' => $feature, 'surface' => $surface];
    }

    /**
     * Determine whether API-token ability policy is intentionally configured.
     */
    private function apiTokenAbilitiesReady(
        AuthConfiguration $configuration,
        ?object $provider,
    ): bool {
        if (! $provider instanceof ApiTokenAbilityProvider) {
            return false;
        }

        if (! $provider instanceof ConfiguredApiTokenAbilityProvider) {
            return true;
        }

        $abilities = $configuration->get('features.api_tokens.settings.abilities', []);

        if (! is_array($abilities) || $abilities === []) {
            return false;
        }

        foreach ($abilities as $ability) {
            if (! is_string($ability) || trim($ability) === '' || mb_strlen($ability) > 120) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether the route surface is globally and locally configured.
     */
    private function routeSurfaceConfigured(
        AuthConfiguration $configuration,
        AuthFeature $feature,
        string $surface,
    ): bool {
        return $configuration->enabled()
            && $configuration->boolean('routes.enabled', false)
            && $configuration->boolean("routes.{$surface}.enabled", false)
            && $configuration->featureRoutesEnabled($feature, $surface);
    }

    /**
     * Determine whether at least one social provider has a usable identifier.
     */
    private function hasConfiguredSocialProvider(
        AuthConfiguration $configuration,
        Container $container,
    ): bool {
        $providers = $configuration->get('features.social_identities.settings.providers', []);
        $providerConfiguration = $this->integration($container, SocialProviderConfiguration::class);

        if (! is_array($providers)
            || $providers === []
            || ! $providerConfiguration instanceof SocialProviderConfiguration) {
            return false;
        }

        try {
            foreach (array_keys($providers) as $provider) {
                if (! is_string($provider) || preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $provider) !== 1) {
                    return false;
                }

                $providerConfiguration->provider($provider);
            }
        } catch (Throwable) {
            return false;
        }

        return true;
    }

    /**
     * Return the configured Spatie Permission table inventory.
     *
     * @return list<string>
     */
    private function spatieTables(): array
    {
        $configured = config('permission.table_names', []);

        if (! is_array($configured)) {
            return [];
        }

        return array_values(array_filter([
            $configured['roles'] ?? null,
            $configured['permissions'] ?? null,
            $configured['model_has_permissions'] ?? null,
            $configured['model_has_roles'] ?? null,
            $configured['role_has_permissions'] ?? null,
        ], static fn (mixed $table): bool => is_string($table) && trim($table) !== ''));
    }

    /**
     * Build the canonical route names expected for the current configuration.
     *
     * @return list<string>
     */
    private function expectedRoutes(
        AuthConfiguration $configuration,
        FeatureManifest $manifest,
        FeatureGate $features,
    ): array {
        if (! $configuration->enabled() || ! $configuration->boolean('routes.enabled', false)) {
            return [];
        }

        $routes = [];

        foreach ($manifest->definitions() as $definition) {
            if (! $features->allows($definition->feature, FeatureOperation::Read)) {
                continue;
            }

            foreach ($definition->routeNames as $surface => $names) {
                if (! $configuration->boolean("routes.{$surface}.enabled", false)
                    || ! $configuration->featureRoutesEnabled($definition->feature, $surface)
                    || ! $this->routeDependenciesAvailable($definition, $surface, $features)) {
                    continue;
                }

                foreach ($names as $name) {
                    $routes[] = "nvl.auth.{$surface}.{$name}";
                }
            }
        }

        return $routes;
    }

    /**
     * Determine whether every route-only dependency is effective.
     */
    private function routeDependenciesAvailable(
        FeatureDefinition $definition,
        string $surface,
        FeatureGate $features,
    ): bool {
        foreach ($definition->dependenciesForSurface($surface) as $dependency) {
            if (! $features->allows($dependency, FeatureOperation::Read)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether passkey origins are a non-empty HTTPS URL list.
     */
    private function validOrigins(mixed $origins, mixed $relyingPartyId): bool
    {
        if (! is_array($origins)
            || $origins === []
            || ! is_string($relyingPartyId)
            || ! $this->validRelyingPartyId($relyingPartyId)) {
            return false;
        }

        foreach ($origins as $origin) {
            $host = is_string($origin) ? parse_url($origin, PHP_URL_HOST) : null;
            $path = is_string($origin) ? parse_url($origin, PHP_URL_PATH) : null;

            if (! is_string($origin)
                || filter_var($origin, FILTER_VALIDATE_URL) === false
                || parse_url($origin, PHP_URL_SCHEME) !== 'https'
                || ! is_string($host)
                || ($host !== $relyingPartyId && ! str_ends_with($host, ".{$relyingPartyId}"))
                || (is_string($path) && $path !== '' && $path !== '/')
                || parse_url($origin, PHP_URL_USER) !== null
                || parse_url($origin, PHP_URL_QUERY) !== null
                || parse_url($origin, PHP_URL_FRAGMENT) !== null) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether a passkey relying-party identifier is a hostname.
     */
    private function validRelyingPartyId(mixed $relyingPartyId): bool
    {
        return is_string($relyingPartyId)
            && mb_strlen($relyingPartyId) <= 253
            && preg_match('/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/', $relyingPartyId) === 1;
    }

    /**
     * Determine whether one configuration value is a bounded non-empty string.
     */
    private function boundedString(mixed $value, int $maximum): bool
    {
        return is_string($value)
            && trim($value) !== ''
            && $value === trim($value)
            && mb_strlen($value) <= $maximum;
    }

    /**
     * Return physical principal columns that are also declared Eloquent relationships.
     *
     * @return list<string>
     */
    private function principalAttributeCollisions(
        Container $container,
        Builder $schema,
        string $table,
    ): array {
        $models = $container->make(AuthModelRegistry::class);
        $class = $models->userClass();
        $collisions = [];

        foreach ($schema->getColumnListing($table) as $column) {
            if (! method_exists($class, $column)) {
                continue;
            }

            $returnType = (new ReflectionMethod($class, $column))->getReturnType();

            if ($returnType instanceof ReflectionNamedType
                && ! $returnType->isBuiltin()
                && is_a($returnType->getName(), Relation::class, true)) {
                $collisions[] = $column;
            }
        }

        return $collisions;
    }

    /**
     * Determine whether a named schema index has the required uniqueness.
     */
    private function indexReady(
        Builder $schema,
        string $table,
        string $name,
        bool $unique,
    ): bool {
        return collect($schema->getIndexes($table))->contains(
            static fn (array $index): bool => $index['name'] === $name
                && $index['unique'] === $unique,
        );
    }

    /**
     * Validate explicit or Laravel-derived passkey user-handle key material.
     */
    private function validPasskeyUserHandleKey(
        AuthConfiguration $configuration,
        Container $container,
    ): bool {
        $configured = $configuration->get('features.passkeys.settings.user_handle_key');
        $application = $container->make(ConfigRepository::class);
        $key = is_string($configured) && trim($configured) !== ''
            ? $configured
            : $application->get('app.key');

        if (! is_string($key) || trim($key) === '') {
            return false;
        }

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);
            $key = is_string($decoded) ? $decoded : '';
        }

        return strlen($key) >= 32;
    }
}
