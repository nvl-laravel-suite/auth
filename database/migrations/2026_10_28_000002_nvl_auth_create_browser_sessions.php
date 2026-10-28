<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Support\Config\PackageStorage;

return new class extends Migration implements AuthSchemaMigration
{
    public function getConnection(): ?string
    {
        return PackageStorage::connection('auth');
    }

    public function up(): void
    {
        if (config('nvl-auth.migrations.install_all') !== true && config('nvl-auth.features.managed_sessions.enabled') !== true) {
            return;
        }
        $schema = Schema::connection($this->getConnection());
        if ($schema->hasTable(AuthTables::BrowserSessions)) {
            return;
        }
        $schema->create(AuthTables::BrowserSessions, function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('subject_type', 160);
            $table->string('subject_id', 191);
            $table->string('guard_name', 128);
            $table->char('provider_hash', 64);
            $table->char('binding_hash', 64)->unique('nvl_auth_browser_binding_unique');
            $table->unsignedBigInteger('security_revision');
            $table->uuid('session_family_id')->index('nvl_auth_browser_family_index');
            $table->string('method', 80);
            $table->text('assurance');
            $table->text('ip_address')->nullable();
            $table->text('user_agent')->nullable();
            $table->timestampTz('authenticated_at');
            $table->timestampTz('last_seen_at');
            $table->timestampTz('absolute_expires_at')->index('nvl_auth_browser_expiry_index');
            $table->timestampTz('revoked_at')->nullable();
            $table->timestampsTz();
            $table->index(['subject_type', 'subject_id', 'guard_name', 'revoked_at'], 'nvl_auth_browser_subject_index');
        });
    }

    public function down(): void {}
};
