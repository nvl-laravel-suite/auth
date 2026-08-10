<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Enums\AuthFeature;
use RuntimeException;

/** Plans and installs only schema required by currently enabled Auth features. */
final readonly class AuthSchemaManager
{
    public function __construct(private AuthConfiguration $configuration) {}

    /**
     * @return array{mode: 'apply'|'plan', required: list<string>, existing: list<string>, missing: list<string>, created: list<string>}
     */
    public function execute(bool $apply = false): array
    {
        $required = $this->requiredTables();
        $schema = Schema::connection($this->connectionName());
        $existing = array_values(array_filter(
            $required,
            static fn (string $table): bool => $schema->hasTable($table),
        ));
        $missing = array_values(array_diff($required, $existing));

        if ($apply && $missing !== []) {
            if (! $this->configuration->boolean('migrations.enabled', true)) {
                throw new RuntimeException(
                    'Auth schema apply is unavailable while migrations are host-owned. '
                    .'Update and run the published host migrations, then rerun the schema plan.',
                );
            }

            $this->migration('2026_08_01_000000_create_nvl_auth_identity_tables.php')->up();
            $this->migration('2026_08_02_000000_create_nvl_auth_tables.php')->up();
        }

        $remaining = array_values(array_filter(
            $required,
            static fn (string $table): bool => ! $schema->hasTable($table),
        ));

        if ($apply && $remaining !== []) {
            throw new RuntimeException(sprintf(
                'Auth schema installation did not create required table(s): %s.',
                implode(', ', $remaining),
            ));
        }

        return [
            'mode' => $apply ? 'apply' : 'plan',
            'required' => $required,
            'existing' => $existing,
            'missing' => $missing,
            'created' => $apply ? $missing : [],
        ];
    }

    /**
     * @return list<string>
     */
    public function requiredTables(): array
    {
        $tables = [];

        if ($this->enabled(AuthFeature::PrincipalManagement)) {
            $tables[] = $this->table('users', 'nvl_auth_users');
        }

        if ($this->enabled(AuthFeature::Password)) {
            $tables[] = $this->table('password_reset_tokens', 'nvl_auth_password_reset_tokens');
        }

        if ($this->enabled(AuthFeature::Rbac)) {
            foreach ([
                'permissions' => 'nvl_auth_permissions',
                'roles' => 'nvl_auth_roles',
                'model_has_permissions' => 'nvl_auth_model_has_permissions',
                'model_has_roles' => 'nvl_auth_model_has_roles',
                'role_has_permissions' => 'nvl_auth_role_has_permissions',
            ] as $key => $default) {
                $tables[] = $this->table($key, $default);
            }
        }

        if ($this->enabled(AuthFeature::ApiTokens)) {
            $tables[] = $this->table('personal_access_tokens', 'nvl_auth_personal_access_tokens');
        }

        if ($this->enabled(AuthFeature::Clients) || $this->enabled(AuthFeature::Audit)) {
            $tables[] = 'nvl_auth_clients';
        }

        if ($this->enabled(AuthFeature::Clients)) {
            $tables[] = 'nvl_auth_client_sessions';
        }

        if ($this->enabled(AuthFeature::Invitations)) {
            $tables[] = 'nvl_auth_invitations';
        }

        if ($this->enabled(AuthFeature::MagicLinks) || $this->enabled(AuthFeature::SecurityCodes)) {
            $tables[] = 'nvl_auth_challenges';
        }

        if ($this->enabled(AuthFeature::Totp)) {
            $tables[] = 'nvl_auth_totp_credentials';
        }

        if ($this->enabled(AuthFeature::Passkeys)) {
            $tables[] = 'nvl_auth_passkeys';
        }

        if ($this->enabled(AuthFeature::RecoveryCodes)) {
            $tables[] = 'nvl_auth_recovery_codes';
        }

        if ($this->enabled(AuthFeature::SocialIdentities)) {
            $tables[] = 'nvl_auth_social_identities';
        }

        if ($this->enabled(AuthFeature::Audit)) {
            $tables[] = 'nvl_auth_audits';
        }

        return array_values(array_unique($tables));
    }

    private function enabled(AuthFeature $feature): bool
    {
        return $this->configuration->featureEnabled($feature);
    }

    private function table(string $key, string $default): string
    {
        return $this->configuration->string("tables.{$key}", $default);
    }

    private function connectionName(): ?string
    {
        $connection = $this->configuration->get('connection');

        return is_string($connection) && trim($connection) !== ''
            ? trim($connection)
            : null;
    }

    private function migration(string $filename): AuthSchemaMigration
    {
        $migration = require dirname(__DIR__, 2).'/database/migrations/'.$filename;

        if (! $migration instanceof AuthSchemaMigration) {
            throw new RuntimeException("Auth schema migration [{$filename}] is invalid.");
        }

        return $migration;
    }
}
