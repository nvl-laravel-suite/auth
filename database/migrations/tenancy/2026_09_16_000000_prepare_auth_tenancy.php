<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Definitions\Tables\AuthTables;

return new class extends Migration
{
    /** Prepare independently selected Auth ownership storage. */
    public function up(): void
    {
        $schema = Schema::connection($this->connectionName());

        if (! $schema->hasTable(AuthTables::TenantMemberships)) {
            $schema->create(AuthTables::TenantMemberships, static function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->uuid('tenant_id');
                $table->string('subject_type', 160);
                $table->string('subject_id', 191);
                $table->string('status', 16)->default('active');
                $table->boolean('is_owner')->default(false);
                $table->unsignedBigInteger('revision')->default(1);
                $table->timestampsTz();
                $table->unique(['tenant_id', 'subject_type', 'subject_id'], 'nvl_auth_memberships_tenant_subject_unique');
                $table->index(['subject_type', 'subject_id', 'status', 'tenant_id'], 'nvl_auth_memberships_subject_status_index');
                $table->index(['tenant_id', 'status', 'is_owner'], 'nvl_auth_memberships_owner_index');
            });
        }

        if (! $schema->hasTable(AuthTables::TenantMembershipLocks)) {
            $schema->create(AuthTables::TenantMembershipLocks, static function (Blueprint $table): void {
                $table->uuid('tenant_id')->primary();
                $table->timestampsTz();
            });
        }

        if (! $schema->hasTable(AuthTables::TenantAuthenticationIntents)) {
            $schema->create(AuthTables::TenantAuthenticationIntents, static function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->uuid('tenant_id');
                $table->string('purpose', 32);
                $table->char('nonce_hash', 64)->unique();
                $table->char('session_binding_hash', 64);
                $table->string('subject_type', 160)->nullable();
                $table->string('subject_id', 191)->nullable();
                $table->text('payload')->nullable();
                $table->timestampTz('expires_at');
                $table->timestampTz('consumed_at')->nullable();
                $table->timestampsTz();
                $table->index(['tenant_id', 'purpose', 'expires_at'], 'nvl_auth_intents_tenant_expiry_index');
                $table->index('expires_at', 'nvl_auth_intents_expiry_index');
            });
        }

        $this->addTenantColumn($schema, AuthTables::Roles);
        $this->addTenantColumn($schema, AuthTables::ModelHasRoles);
        $this->addTenantColumn($schema, AuthTables::ModelHasPermissions);

        foreach ([AuthTables::Invitations, AuthTables::PersonalAccessTokens, AuthTables::Challenges, AuthTables::Audits] as $table) {
            $this->addMixedOwnershipColumns($schema, $table);
        }
    }

    /** Remove only the independently selected Auth ownership additions. */
    public function down(): void
    {
        $schema = Schema::connection($this->connectionName());
        $schema->dropIfExists(AuthTables::TenantAuthenticationIntents);
        $schema->dropIfExists(AuthTables::TenantMembershipLocks);
        $schema->dropIfExists(AuthTables::TenantMemberships);
    }

    /** Add the nullable preparation discriminator to one existing tenant table. */
    private function addTenantColumn($schema, string $table): void
    {
        if ($schema->hasTable($table) && ! $schema->hasColumn($table, 'tenant_id')) {
            $schema->table($table, static function (Blueprint $blueprint): void {
                $blueprint->uuid('tenant_id')->nullable();
            });
        }
    }

    /** Add explicit mixed ownership preparation columns and read indexes. */
    private function addMixedOwnershipColumns($schema, string $table): void
    {
        if (! $schema->hasTable($table)) {
            return;
        }

        $hasTenant = $schema->hasColumn($table, 'tenant_id');
        $hasOwnership = $schema->hasColumn($table, 'ownership_key');
        if ($hasTenant && $hasOwnership) {
            return;
        }

        $schema->table($table, static function (Blueprint $blueprint) use ($hasTenant, $hasOwnership, $table): void {
            if (! $hasTenant) {
                $blueprint->uuid('tenant_id')->nullable();
            }
            if (! $hasOwnership) {
                $blueprint->string('ownership_key', 43)->default('platform');
            }
            $blueprint->index(['ownership_key', 'created_at'], substr($table.'_ownership_created_index', 0, 63));
        });
    }

    /** Resolve the package's immutable operational connection. */
    private function connectionName(): ?string
    {
        $connection = Config::get('nvl-auth.connection');

        return is_string($connection) && trim($connection) !== '' ? trim($connection) : null;
    }
};
