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

    /** Install mandatory proof storage without altering immutable historical feature conditions. */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());
        $name = AuthTables::get(AuthTables::Challenges);
        if (! $schema->hasTable($name)) {
            $schema->create($name, static function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('type', 80);
                $table->string('purpose', 120);
                $table->string('subject_type', 160)->nullable();
                $table->string('subject_id', 191)->nullable();
                $table->char('recipient_hash', 64)->nullable();
                $table->char('secret_hash', 64)->unique();
                $table->char('secondary_secret_hash', 64)->nullable()->unique('nvl_auth_challenges_secondary_secret_hash_unique');
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
        $required = ['id', 'type', 'purpose', 'subject_type', 'subject_id', 'recipient_hash', 'secret_hash', 'active_key', 'payload', 'attempts', 'max_attempts', 'expires_at', 'consumed_at', 'revoked_at', 'created_at', 'updated_at'];
        if (! $schema->hasColumns($name, $required)) {
            throw new RuntimeException('Partial authentication challenge storage requires a data-preserving host migration.');
        }
        if (! $schema->hasColumn($name, 'secondary_secret_hash')) {
            $schema->table($name, static fn (Blueprint $table) => $table->char('secondary_secret_hash', 64)->nullable());
        }
        if (! $schema->hasIndex($name, 'nvl_auth_challenges_secondary_secret_hash_unique')) {
            $schema->table($name, static fn (Blueprint $table) => $table->unique('secondary_secret_hash', 'nvl_auth_challenges_secondary_secret_hash_unique'));
        }
    }

    /** Retained proofs and generic business challenges survive package rollback. */
    public function down(): void {}
};
