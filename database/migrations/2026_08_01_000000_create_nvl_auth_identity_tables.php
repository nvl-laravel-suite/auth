<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Definitions\Tables\AuthTables;

return new class extends Migration implements AuthSchemaMigration
{
    /**
     * Create the package-owned principal, RBAC, and Sanctum schema.
     */
    public function up(): void
    {
        $schema = Schema::connection($this->connectionName());
        $tables = $this->tables();

        if ($this->featureEnabled('principal_management') && ! $schema->hasTable($tables['users'])) {
            $schema->create($tables['users'], function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('name', 160);
                $table->string('email', 254)->unique();
                $table->timestampTz('email_verified_at')->nullable();
                $table->string('password')->nullable();
                $table->boolean('is_active')->default(true);
                $table->string('locale', 12)->default('en');
                $table->string('timezone', 64)->default('UTC');
                $table->json('profile')->nullable();
                $table->json('preferences')->nullable();
                $table->timestampTz('last_login_at')->nullable();
                $table->text('last_login_ip')->nullable();
                $table->timestampTz('locked_until')->nullable();
                $table->rememberToken();
                $table->timestampsTz();
                $table->softDeletesTz();

                $table->index(['is_active', 'deleted_at'], 'nvl_auth_users_active_deleted_index');
                $table->index(['locked_until', 'is_active'], 'nvl_auth_users_lock_index');
                $table->index(['name', 'email'], 'nvl_auth_users_suggestion_index');
            });
        }

        if ($this->featureEnabled('rbac')) {
            if (! $schema->hasTable($tables['permissions'])) {
                $schema->create($tables['permissions'], function (Blueprint $table): void {
                    $table->uuid('id')->primary();
                    $table->string('name', 160);
                    $table->string('guard_name', 80);
                    $table->string('display_name', 160)->nullable();
                    $table->text('description')->nullable();
                    $table->string('group', 120)->nullable();
                    $table->boolean('is_system')->default(false);
                    $table->json('metadata')->nullable();
                    $table->timestampsTz();

                    $table->unique(['name', 'guard_name'], 'nvl_auth_permissions_name_guard_unique');
                    $table->index(['group', 'guard_name'], 'nvl_auth_permissions_group_guard_index');
                });
            }

            $rolesCreated = false;

            if (! $schema->hasTable($tables['roles'])) {
                $schema->create($tables['roles'], function (Blueprint $table): void {
                    $table->uuid('id')->primary();
                    $table->string('name', 160);
                    $table->string('guard_name', 80);
                    $table->string('display_name', 160)->nullable();
                    $table->text('description')->nullable();
                    $table->uuid('parent_id')->nullable();
                    $table->integer('priority')->default(0);
                    $table->boolean('is_system')->default(false);
                    $table->json('metadata')->nullable();
                    $table->timestampsTz();

                    $table->unique(['name', 'guard_name'], 'nvl_auth_roles_name_guard_unique');
                    $table->index(['parent_id', 'priority'], 'nvl_auth_roles_hierarchy_index');
                });
                $rolesCreated = true;
            }

            // PostgreSQL compiles self-referencing foreign keys before primary-key
            // commands inside one create-table blueprint. Add the relation only
            // after the referenced primary key has been created.
            if ($rolesCreated) {
                $schema->table($tables['roles'], function (Blueprint $table) use ($tables): void {
                    $table->foreign('parent_id', 'nvl_auth_roles_parent_id_foreign')
                        ->references('id')
                        ->on($tables['roles'])
                        ->nullOnDelete();
                });
            }

            if (! $schema->hasTable($tables['model_has_permissions'])) {
                $schema->create($tables['model_has_permissions'], function (Blueprint $table) use ($tables): void {
                    $table->foreignUuid('permission_id')->constrained($tables['permissions'])->cascadeOnDelete();
                    $table->string('model_type', 160);
                    $table->uuid('model_id');

                    $table->primary(['permission_id', 'model_id', 'model_type'], 'nvl_auth_model_permissions_primary');
                    $table->index(['model_id', 'model_type'], 'nvl_auth_model_permissions_model_index');
                });
            }

            if (! $schema->hasTable($tables['model_has_roles'])) {
                $schema->create($tables['model_has_roles'], function (Blueprint $table) use ($tables): void {
                    $table->foreignUuid('role_id')->constrained($tables['roles'])->cascadeOnDelete();
                    $table->string('model_type', 160);
                    $table->uuid('model_id');

                    $table->primary(['role_id', 'model_id', 'model_type'], 'nvl_auth_model_roles_primary');
                    $table->index(['model_id', 'model_type'], 'nvl_auth_model_roles_model_index');
                });
            }

            if (! $schema->hasTable($tables['role_has_permissions'])) {
                $schema->create($tables['role_has_permissions'], function (Blueprint $table) use ($tables): void {
                    $table->foreignUuid('permission_id')->constrained($tables['permissions'])->cascadeOnDelete();
                    $table->foreignUuid('role_id')->constrained($tables['roles'])->cascadeOnDelete();

                    $table->primary(['permission_id', 'role_id'], 'nvl_auth_role_permissions_primary');
                });
            }
        }

        if ($this->featureEnabled('api_tokens') && ! $schema->hasTable($tables['personal_access_tokens'])) {
            $schema->create($tables['personal_access_tokens'], function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('tokenable_type', 160);
                $table->uuid('tokenable_id');
                $table->string('name');
                $table->string('token', 64)->unique();
                $table->text('abilities')->nullable();
                $table->timestampTz('last_used_at')->nullable();
                $table->timestampTz('expires_at')->nullable();
                $table->timestampsTz();

                $table->index(['tokenable_type', 'tokenable_id'], 'nvl_auth_tokens_tokenable_index');
                $table->index('expires_at', 'nvl_auth_tokens_expiry_index');
            });
        }

        if ($this->featureEnabled('password') && ! $schema->hasTable($tables['password_reset_tokens'])) {
            $schema->create($tables['password_reset_tokens'], function (Blueprint $table): void {
                $table->string('email', 254)->primary();
                $table->string('token');
                $table->timestampTz('created_at')->nullable();
            });
        }
    }

    /**
     * Drop the package-owned identity schema in dependency order.
     */
    public function down(): void
    {
        $schema = Schema::connection($this->connectionName());

        $tables = $this->tables();

        foreach (array_reverse(array_values($tables)) as $table) {
            $schema->dropIfExists($table);
        }
    }

    /**
     * Resolve and validate the immutable package identity table map.
     *
     * @return array{
     *     users: string,
     *     permissions: string,
     *     roles: string,
     *     model_has_permissions: string,
     *     model_has_roles: string,
     *     role_has_permissions: string,
     *     personal_access_tokens: string,
     *     password_reset_tokens: string
     * }
     */
    private function tables(): array
    {
        $defaults = [
            'users' => AuthTables::Users,
            'permissions' => AuthTables::Permissions,
            'roles' => AuthTables::Roles,
            'model_has_permissions' => AuthTables::ModelHasPermissions,
            'model_has_roles' => AuthTables::ModelHasRoles,
            'role_has_permissions' => AuthTables::RoleHasPermissions,
            'personal_access_tokens' => AuthTables::PersonalAccessTokens,
            'password_reset_tokens' => AuthTables::PasswordResetTokens,
        ];
        $tables = [];

        foreach ($defaults as $key => $default) {
            $configured = Config::get("nvl-auth.tables.{$key}", $default);

            if (! is_string($configured)
                || preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,62}$/', $configured) !== 1) {
                throw new RuntimeException("Auth table [{$key}] must be a valid database identifier of at most 63 characters.");
            }

            $tables[$key] = $configured;
        }

        if (count(array_unique($tables)) !== count($tables)) {
            throw new RuntimeException('Auth identity table names must be unique.');
        }

        return $tables;
    }

    /**
     * Resolve the package's optional operational connection.
     */
    private function connectionName(): ?string
    {
        $connection = Config::get('nvl-auth.connection');

        return is_string($connection) && trim($connection) !== ''
            ? trim($connection)
            : null;
    }

    /**
     * Determine whether one independently adoptable schema capability is enabled.
     */
    private function featureEnabled(string $feature): bool
    {
        return Config::get('nvl-auth.migrations.install_all', false) === true
            || Config::get("nvl-auth.features.{$feature}.enabled", false) === true;
    }
};
