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
        if (config('nvl-auth.migrations.install_all') !== true && config('nvl-auth.features.impersonation.enabled') !== true) {
            return;
        }
        $schema = Schema::connection($this->getConnection());
        if ($schema->hasTable(AuthTables::Impersonations)) {
            return;
        }
        $schema->create(AuthTables::Impersonations, function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('actor_type', 160);
            $table->string('actor_id', 191);
            $table->string('effective_subject_type', 160);
            $table->string('effective_subject_id', 191);
            $table->uuid('browser_session_id')->index('nvl_auth_impersonation_browser_index');
            $table->string('guard_name', 128);
            $table->unsignedBigInteger('actor_revision');
            $table->unsignedBigInteger('target_revision');
            $table->text('reason');
            $table->text('owner_reference')->nullable();
            $table->char('active_session_key', 64)->nullable()->unique('nvl_auth_impersonation_active_unique');
            $table->timestampTz('started_at');
            $table->timestampTz('expires_at')->index('nvl_auth_impersonation_expiry_index');
            $table->timestampTz('stopped_at')->nullable();
            $table->string('stop_reason', 80)->nullable();
            $table->timestampsTz();
            $table->index(['actor_type', 'actor_id', 'stopped_at'], 'nvl_auth_impersonation_actor_index');
        });
    }

    public function down(): void {}
};
