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
        if (config('nvl-auth.migrations.install_all') !== true && config('nvl-auth.features.email_verification.enabled') !== true) {
            return;
        }
        $schema = Schema::connection($this->getConnection());
        $name = AuthTables::PendingEmailChanges;
        if ($schema->hasTable($name)) {
            return;
        }
        $schema->create($name, function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('subject_type', 160);
            $table->string('subject_id', 191);
            $table->text('new_email');
            $table->char('email_hash', 64);
            $table->char('token_hash', 64)->unique();
            $table->unsignedBigInteger('security_revision');
            $table->char('active_key', 64)->nullable()->unique('nvl_auth_pending_email_active_unique');
            $table->text('context');
            $table->timestampTz('expires_at');
            $table->timestampTz('consumed_at')->nullable();
            $table->timestampTz('revoked_at')->nullable();
            $table->timestampsTz();
            $table->index(['subject_type', 'subject_id', 'created_at'], 'nvl_auth_pending_email_subject_index');
            $table->index('expires_at', 'nvl_auth_pending_email_expiry_index');
        });
    }

    /** Retain proof history; explicit retention owns deletion. */
    public function down(): void {}
};
