<?php

declare(strict_types=1);
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Services\PrincipalSecuritySchema;
use Nvl\Support\Config\PackageStorage;

return new class extends Migration implements AuthSchemaMigration
{
    private const INDEX = 'nvl_auth_principal_security_states_subject_unique';

    public function getConnection(): ?string
    {
        return PackageStorage::connection('auth');
    }

    /** Install mandatory state; repair missing nonidentity fields without rewriting retained revisions. */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());
        $name = AuthTables::PrincipalSecurityStates;
        if (! $schema->hasTable($name)) {
            $schema->create($name, function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('subject_type', 160);
                $table->string('subject_id', 191);
                $table->unsignedBigInteger('revision')->default(1);
                $table->timestampsTz();
                $table->unique(['subject_type', 'subject_id'], self::INDEX);
            });

            return;
        }
        if (! $schema->hasColumns($name, ['id', 'subject_type', 'subject_id'])) {
            throw new RuntimeException('Security state identity columns require a data-preserving host migration.');
        }
        if ($schema->hasIndex($name, self::INDEX) && ! PrincipalSecuritySchema::indexReady($schema)) {
            throw new RuntimeException('Security state requires a full unique subject index on (subject_type, subject_id); repair the conflicting host index without rewriting data.');
        }
        foreach (['revision', 'created_at', 'updated_at'] as $column) {
            if (! $schema->hasColumn($name, $column)) {
                $schema->table($name, function (Blueprint $table) use ($column): void {
                    if ($column === 'revision') {
                        $table->unsignedBigInteger('revision')->default(1);
                    } else {
                        $table->timestampTz($column)->nullable();
                    }
                });
            }
        }
        if (! $schema->hasIndex($name, self::INDEX)) {
            $schema->table($name, fn (Blueprint $table) => $table->unique(['subject_type', 'subject_id'], self::INDEX));
        }
    }

    /** Retained state must never be dropped while a principal or dependent capability can survive. */
    public function down(): void {}
};
