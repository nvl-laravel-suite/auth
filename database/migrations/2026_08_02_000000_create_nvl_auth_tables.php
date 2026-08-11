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
     * Create the complete package-owned Auth schema.
     */
    public function up(): void
    {
        $schema = Schema::connection($this->connectionName());

        if (($this->featureEnabled('clients') || $this->featureEnabled('audit'))
            && ! $schema->hasTable(AuthTables::Clients)) {
            $schema->create(AuthTables::Clients, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('name', 120);
                $table->string('surface', 40)->default('web');
                $table->string('base_url', 2048);
                $table->json('return_paths')->nullable();
                $table->json('allowed_origins')->nullable();
                $table->json('allowed_flows')->nullable();
                $table->json('metadata')->nullable();
                $table->boolean('is_active')->default(true);
                $table->timestampTz('last_used_at')->nullable();
                $table->timestampsTz();

                $table->index(['is_active', 'surface'], 'nvl_auth_clients_active_surface_index');
            });
        }

        if ($this->featureEnabled('clients') && ! $schema->hasTable(AuthTables::ClientSessions)) {
            $schema->create(AuthTables::ClientSessions, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->foreignUuid('client_id')->constrained(AuthTables::Clients)->cascadeOnDelete();
                $table->string('subject_type', 160)->nullable();
                $table->string('subject_id', 191)->nullable();
                $table->char('session_id_hash', 64);
                $table->text('ip_address')->nullable();
                $table->text('user_agent')->nullable();
                $table->text('metadata')->nullable();
                $table->timestampTz('authenticated_at')->nullable();
                $table->timestampTz('last_seen_at');
                $table->timestampTz('ended_at')->nullable();
                $table->string('end_reason', 80)->nullable();
                $table->timestampsTz();

                $table->unique(['client_id', 'session_id_hash'], 'nvl_auth_client_sessions_client_hash_unique');
                $table->index(['subject_type', 'subject_id', 'ended_at'], 'nvl_auth_client_sessions_subject_index');
                $table->index(['ended_at', 'last_seen_at'], 'nvl_auth_client_sessions_lifecycle_index');
            });
        }

        if ($this->featureEnabled('invitations') && ! $schema->hasTable(AuthTables::Invitations)) {
            $schema->create(AuthTables::Invitations, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->char('token_hash', 64)->unique();
                $table->char('active_key', 64)->nullable()->unique();
                $table->text('recipient');
                $table->char('recipient_hash', 64);
                $table->char('context_hash', 64)->nullable()->index();
                $table->string('type', 80)->default('registration');
                $table->string('purpose', 120)->default('registration');
                $table->string('inviter_type', 160)->nullable();
                $table->string('inviter_id', 191)->nullable();
                $table->string('accepted_by_type', 160)->nullable();
                $table->string('accepted_by_id', 191)->nullable();
                $table->json('roles')->nullable();
                $table->json('permissions')->nullable();
                $table->text('metadata')->nullable();
                $table->unsignedSmallInteger('resend_count')->default(0);
                $table->timestampTz('last_sent_at')->nullable();
                $table->timestampTz('expires_at');
                $table->timestampTz('accepted_at')->nullable();
                $table->timestampTz('revoked_at')->nullable();
                $table->timestampsTz();

                $table->index(['recipient_hash', 'expires_at'], 'nvl_auth_invitations_recipient_index');
                $table->index(['expires_at', 'accepted_at', 'revoked_at'], 'nvl_auth_invitations_lifecycle_index');
                $table->index(['inviter_type', 'inviter_id'], 'nvl_auth_invitations_inviter_index');
            });
        }

        if (($this->featureEnabled('magic_links') || $this->featureEnabled('security_codes'))
            && ! $schema->hasTable(AuthTables::Challenges)) {
            $schema->create(AuthTables::Challenges, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('type', 80);
                $table->string('purpose', 120);
                $table->string('subject_type', 160)->nullable();
                $table->string('subject_id', 191)->nullable();
                $table->char('recipient_hash', 64)->nullable();
                $table->char('secret_hash', 64)->unique();
                $table->char('secondary_secret_hash', 64)->nullable()->unique();
                $table->char('active_key', 64)->nullable()->unique();
                $table->text('payload')->nullable();
                $table->unsignedSmallInteger('attempts')->default(0);
                $table->unsignedSmallInteger('max_attempts')->default(5);
                $table->timestampTz('expires_at');
                $table->timestampTz('consumed_at')->nullable();
                $table->timestampTz('revoked_at')->nullable();
                $table->timestampsTz();

                $table->index(['type', 'purpose', 'expires_at'], 'nvl_auth_challenges_type_expiry_index');
                $table->index(['subject_type', 'subject_id', 'type'], 'nvl_auth_challenges_subject_index');
                $table->index(['recipient_hash', 'type', 'expires_at'], 'nvl_auth_challenges_recipient_index');
            });
        }

        if ($this->featureEnabled('totp') && ! $schema->hasTable(AuthTables::TotpCredentials)) {
            $schema->create(AuthTables::TotpCredentials, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('subject_type', 160);
                $table->string('subject_id', 191);
                $table->string('name', 120)->nullable();
                $table->text('secret');
                $table->string('algorithm', 16)->default('sha1');
                $table->unsignedTinyInteger('digits')->default(6);
                $table->unsignedSmallInteger('period')->default(30);
                $table->unsignedTinyInteger('allowed_drift')->default(1);
                $table->unsignedBigInteger('last_accepted_timestep')->nullable();
                $table->timestampTz('confirmed_at')->nullable();
                $table->timestampTz('last_used_at')->nullable();
                $table->timestampTz('revoked_at')->nullable();
                $table->timestampsTz();

                $table->index(['subject_type', 'subject_id', 'revoked_at'], 'nvl_auth_totp_subject_index');
            });
        }

        if ($this->featureEnabled('passkeys') && ! $schema->hasTable(AuthTables::Passkeys)) {
            $schema->create(AuthTables::Passkeys, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('subject_type', 160);
                $table->string('subject_id', 191);
                $table->string('name', 120)->nullable();
                $table->text('credential_id');
                $table->char('credential_id_hash', 64)->unique();
                $table->longText('public_key');
                $table->text('user_handle');
                $table->unsignedBigInteger('signature_counter')->default(0);
                $table->json('transports')->nullable();
                $table->boolean('backup_eligible')->default(false);
                $table->boolean('backed_up')->default(false);
                $table->timestampTz('last_used_at')->nullable();
                $table->timestampTz('revoked_at')->nullable();
                $table->timestampsTz();

                $table->index(['subject_type', 'subject_id', 'revoked_at'], 'nvl_auth_passkeys_subject_index');
            });
        }

        if ($this->featureEnabled('recovery_codes') && ! $schema->hasTable(AuthTables::RecoveryCodes)) {
            $schema->create(AuthTables::RecoveryCodes, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->uuid('batch_id');
                $table->string('subject_type', 160);
                $table->string('subject_id', 191);
                $table->char('code_hash', 64)->unique();
                $table->timestampTz('used_at')->nullable();
                $table->timestampTz('revoked_at')->nullable();
                $table->timestampsTz();

                $table->index(['subject_type', 'subject_id', 'batch_id'], 'nvl_auth_recovery_codes_subject_index');
                $table->index(['used_at', 'revoked_at'], 'nvl_auth_recovery_codes_lifecycle_index');
            });
        }

        if ($this->featureEnabled('social_identities') && ! $schema->hasTable(AuthTables::SocialIdentities)) {
            $schema->create(AuthTables::SocialIdentities, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('subject_type', 160);
                $table->string('subject_id', 191);
                $table->string('provider', 80);
                $table->text('provider_user_id');
                $table->char('provider_user_id_hash', 64);
                $table->text('email')->nullable();
                $table->text('profile')->nullable();
                $table->timestampTz('last_used_at')->nullable();
                $table->timestampTz('revoked_at')->nullable();
                $table->timestampsTz();

                $table->unique(['provider', 'provider_user_id_hash'], 'nvl_auth_social_provider_user_unique');
                $table->index(['subject_type', 'subject_id', 'provider'], 'nvl_auth_social_subject_index');
            });
        }

        if ($this->featureEnabled('audit') && ! $schema->hasTable(AuthTables::Audits)) {
            $schema->create(AuthTables::Audits, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('action', 120);
                $table->string('outcome', 40)->default('success');
                $table->string('subject_type', 160)->nullable();
                $table->string('subject_id', 191)->nullable();
                $table->string('actor_type', 160)->nullable();
                $table->string('actor_id', 191)->nullable();
                $table->foreignUuid('client_id')->nullable()->constrained(AuthTables::Clients)->nullOnDelete();
                $table->text('ip_address')->nullable();
                $table->text('user_agent')->nullable();
                $table->string('request_id', 128)->nullable();
                $table->text('metadata')->nullable();
                $table->timestampsTz();

                $table->index(['action', 'created_at'], 'nvl_auth_audits_action_index');
                $table->index(['subject_type', 'subject_id', 'created_at'], 'nvl_auth_audits_subject_index');
                $table->index(['actor_type', 'actor_id', 'created_at'], 'nvl_auth_audits_actor_index');
            });
        }
    }

    /**
     * Drop every package-owned Auth table.
     */
    public function down(): void
    {
        $schema = Schema::connection($this->connectionName());

        foreach ([
            AuthTables::Audits,
            AuthTables::SocialIdentities,
            AuthTables::RecoveryCodes,
            AuthTables::Passkeys,
            AuthTables::TotpCredentials,
            AuthTables::Challenges,
            AuthTables::Invitations,
            AuthTables::ClientSessions,
            AuthTables::Clients,
        ] as $table) {
            $schema->dropIfExists($table);
        }
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
