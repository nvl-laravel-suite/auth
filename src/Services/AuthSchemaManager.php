<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use RuntimeException;

/**
 * Plans and installs only schema required by currently enabled Auth features.
 *
 * @internal
 */
final readonly class AuthSchemaManager
{
    /** @var array<string, list<string>> */
    private const array REQUIRED_COLUMNS = [AuthTables::PrincipalSecurityStates => ['id', 'subject_type', 'subject_id', 'revision', 'created_at', 'updated_at'], AuthTables::Invitations => ['context_hash', 'current_delivery_message_id', 'delivery_status', 'delivery_attempted_at', 'delivered_at', 'delivery_failed_at', 'delivery_failure_code'], AuthTables::Challenges => ['secondary_secret_hash']];

    /** @var array<string, list<string>> */
    private const array REQUIRED_INDEXES = [AuthTables::PrincipalSecurityStates => ['nvl_auth_principal_security_states_subject_unique'], AuthTables::Invitations => ['nvl_auth_invitations_context_hash_index', 'nvl_auth_invitations_delivery_status_index'], AuthTables::Challenges => ['nvl_auth_challenges_secondary_secret_hash_unique']];

    /** Native Auth operation. */
    public function __construct(private AuthConfiguration $configuration) {}

    /**
     * Plan or repair the schema required by enabled Auth features.
     *
     * @return array{mode: 'apply'|'plan', required: list<string>, existing: list<string>, missing: list<string>, outdated: array<string, list<string>>, missing_indexes: array<string, list<string>>, created: list<string>}
     */
    public function execute(bool $apply = false): array
    {
        $required = $this->requiredTables();
        $schema = Schema::connection($this->connectionName());
        $existing = array_values(array_filter($required, static fn (string $table): bool => $schema->hasTable($table)));
        $missing = array_values(array_diff($required, $existing));
        $outdated = $this->outdatedTables($schema, $required);
        $missingIndexes = $this->missingIndexes($schema, $required);
        $requiresRepair = $missing !== [] || $outdated !== [] || $missingIndexes !== [];
        if ($apply && $requiresRepair && ! $this->configuration->boolean('migrations.enabled', true)) {
            throw new RuntimeException('Auth schema apply is unavailable while migrations are host-owned. '.'Update and run the published host migrations, then rerun the schema plan.');
        }
        if ($apply && $this->configuration->boolean('migrations.enabled', true)) {
            if ($missing !== []) {
                $this->migration('2026_08_01_000000_nvl_auth_create_nvl_auth_identity_tables.php')->up();
                $this->migration('2026_08_02_000000_nvl_auth_create_nvl_auth_tables.php')->up();
            }
            $this->migration('2026_08_12_000000_nvl_auth_add_auth_delivery_context_columns.php')->up();
            $this->migration('2026_08_28_000000_nvl_auth_add_invitation_delivery_outcomes.php')->up();
            $this->migration('2026_10_27_000001_nvl_auth_create_principal_security_states.php')->up();
        }
        $remaining = array_values(array_filter($required, static fn (string $table): bool => ! $schema->hasTable($table)));
        $remainingOutdated = $this->outdatedTables($schema, $required);
        $remainingIndexes = $this->missingIndexes($schema, $required);
        if ($apply && ($remaining !== [] || $remainingOutdated !== [] || $remainingIndexes !== [])) {
            throw new RuntimeException(sprintf('Auth schema installation remains incomplete: tables [%s], columns [%s], indexes [%s].', implode(', ', $remaining), $this->formatRequirements($remainingOutdated), $this->formatRequirements($remainingIndexes)));
        }

        return ['mode' => $apply ? 'apply' : 'plan', 'required' => $required, 'existing' => $existing, 'missing' => $missing, 'outdated' => $outdated, 'missing_indexes' => $missingIndexes, 'created' => $apply ? $missing : []];
    }

    /**
     * Return required columns missing from existing enabled-feature tables.
     *
     * @param  list<string>  $required
     * @return array<string, list<string>>
     */
    private function outdatedTables(Builder $schema, array $required): array
    {
        $outdated = [];
        $requirements = self::REQUIRED_COLUMNS;
        foreach ($requirements as $table => $columns) {
            if (! in_array($table, $required, true) || ! $schema->hasTable($table)) {
                continue;
            }
            $missing = array_values(array_filter($columns, static fn (string $column): bool => ! $schema->hasColumn($table, $column)));
            if ($missing !== []) {
                $outdated[$table] = $missing;
            }
        }

        return $outdated;
    }

    /**
     * Return required indexes missing from existing enabled-feature tables.
     *
     * @param  list<string>  $required
     * @return array<string, list<string>>
     */
    private function missingIndexes(Builder $schema, array $required): array
    {
        $missingIndexes = [];
        foreach (self::REQUIRED_INDEXES as $table => $indexes) {
            if (! in_array($table, $required, true) || ! $schema->hasTable($table)) {
                continue;
            }
            $missing = array_values(array_filter($indexes, static fn (string $index): bool => $table === AuthTables::PrincipalSecurityStates ? ! PrincipalSecuritySchema::indexReady($schema) : ! $schema->hasIndex($table, $index)));
            if ($missing !== []) {
                $missingIndexes[$table] = $missing;
            }
        }

        return $missingIndexes;
    }

    /**
     * Format a table-keyed requirement map for operator failures.
     *
     * @param  array<string, list<string>>  $requirements
     */
    private function formatRequirements(array $requirements): string
    {
        $formatted = [];
        foreach ($requirements as $table => $items) {
            $formatted[] = $table.':'.implode('|', $items);
        }

        return implode(', ', $formatted);
    }

    /**
     * Return the unique tables required by enabled Auth features.
     *
     * @return list<string>
     */
    public function requiredTables(): array
    {
        $tables = [AuthTables::PrincipalSecurityStates];
        if ($this->enabled(AuthFeature::PrincipalManagement)) {
            $tables[] = $this->table('users', AuthTables::get(AuthTables::Users));
        }
        if ($this->enabled(AuthFeature::Password)) {
            $tables[] = $this->table('password_reset_tokens', AuthTables::get(AuthTables::PasswordResetTokens));
        }
        if ($this->enabled(AuthFeature::Rbac)) {
            foreach (['permissions' => AuthTables::get(AuthTables::Permissions), 'roles' => AuthTables::get(AuthTables::Roles), 'model_has_permissions' => AuthTables::get(AuthTables::ModelHasPermissions), 'model_has_roles' => AuthTables::get(AuthTables::ModelHasRoles), 'role_has_permissions' => AuthTables::get(AuthTables::RoleHasPermissions)] as $key => $default) {
                $tables[] = $this->table($key, $default);
            }
        }
        if ($this->enabled(AuthFeature::ApiTokens)) {
            $tables[] = $this->table('personal_access_tokens', AuthTables::get(AuthTables::PersonalAccessTokens));
        }
        if ($this->enabled(AuthFeature::Clients) || $this->enabled(AuthFeature::Audit)) {
            $tables[] = AuthTables::get(AuthTables::Clients);
        }
        if ($this->enabled(AuthFeature::Clients)) {
            $tables[] = AuthTables::get(AuthTables::ClientSessions);
        }
        if ($this->enabled(AuthFeature::Invitations)) {
            $tables[] = AuthTables::get(AuthTables::Invitations);
        }
        if ($this->enabled(AuthFeature::MagicLinks) || $this->enabled(AuthFeature::SecurityCodes)
            || ($this->enabled(AuthFeature::Totp) && $this->enabled(AuthFeature::Sessions))) {
            $tables[] = AuthTables::get(AuthTables::Challenges);
        }
        if ($this->enabled(AuthFeature::Totp)) {
            $tables[] = AuthTables::get(AuthTables::TotpCredentials);
        }
        if ($this->enabled(AuthFeature::Passkeys)) {
            $tables[] = AuthTables::get(AuthTables::Passkeys);
        }
        if ($this->enabled(AuthFeature::RecoveryCodes)) {
            $tables[] = AuthTables::get(AuthTables::RecoveryCodes);
        }
        if ($this->enabled(AuthFeature::SocialIdentities)) {
            $tables[] = AuthTables::get(AuthTables::SocialIdentities);
        }
        if ($this->enabled(AuthFeature::Audit)) {
            $tables[] = AuthTables::get(AuthTables::Audits);
        }

        return array_values(array_unique($tables));
    }

    /** Native Auth operation. */
    private function enabled(AuthFeature $feature): bool
    {
        return $this->configuration->featureEnabled($feature);
    }

    /** Native Auth operation. */
    private function table(string $key, string $default): string
    {
        return $this->configuration->string("tables.{$key}", $default);
    }

    /** Native Auth operation. */
    private function connectionName(): ?string
    {
        $connection = $this->configuration->get('connection');

        return is_string($connection) && trim($connection) !== '' ? trim($connection) : null;
    }

    /** Native Auth operation. */
    private function migration(string $filename): AuthSchemaMigration
    {
        $migration = require dirname(__DIR__, 2).'/database/migrations/'.$filename;
        if (! $migration instanceof AuthSchemaMigration) {
            throw new RuntimeException("Auth schema migration [{$filename}] is invalid.");
        }

        return $migration;
    }
}
