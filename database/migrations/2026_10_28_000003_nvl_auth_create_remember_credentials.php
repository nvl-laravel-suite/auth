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
        if ($schema->hasTable(AuthTables::RememberCredentials)) {
            return;
        }
        $schema->create(AuthTables::RememberCredentials, function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->char('selector', 64)->unique('nvl_auth_remember_selector_unique');
            $table->char('secret_hash', 64);
            $table->string('subject_type', 160);
            $table->string('subject_id', 191);
            $table->string('guard_name', 128);
            $table->char('provider_hash', 64);
            $table->uuid('session_family_id')->index('nvl_auth_remember_family_index');
            $table->unsignedBigInteger('security_revision');
            $table->timestampTz('absolute_expires_at')->index('nvl_auth_remember_expiry_index');
            $table->timestampTz('consumed_at')->nullable();
            $table->timestampTz('revoked_at')->nullable();
            $table->uuid('rotated_to_id')->nullable();
            $table->timestampsTz();
            $table->index(['subject_type', 'subject_id', 'guard_name'], 'nvl_auth_remember_subject_index');
        });
    }

    public function down(): void {}
};
