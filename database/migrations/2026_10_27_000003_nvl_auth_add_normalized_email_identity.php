<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\PrincipalEmailIdentity;
use Nvl\Support\Config\PackageStorage;

return new class extends Migration implements AuthSchemaMigration
{
    public function getConnection(): ?string
    {
        return PackageStorage::connection('auth');
    }

    /** Retained rows are inspected and explicitly adopted, never converted by migration. */
    public function up(): void
    {
        $class = app(AuthModelRegistry::class)->userClass();
        $model = new $class;
        $schema = $model->getConnection()->getSchemaBuilder();
        $name = $model->getTable();
        $column = $model->getEmailIdentityHashName();
        if (! $schema->hasTable($name)) {
            return;
        }
        if (! $schema->hasColumn($name, $column)) {
            $retained = $model->getConnection()->table($name)->exists();
            $schema->table($name, fn (Blueprint $table) => $table->string($column, 64)->nullable($retained));
        }
        if ($schema->hasIndex($name, PrincipalEmailIdentity::INDEX) && ! PrincipalEmailIdentity::indexReady($model)) {
            throw new RuntimeException('Canonical email identity requires the exact unconditional unique index; repair the host schema without rewriting records.');
        }
        if (! $schema->hasIndex($name, PrincipalEmailIdentity::INDEX)) {
            $schema->table($name, fn (Blueprint $table) => $table->unique([$column], PrincipalEmailIdentity::INDEX));
        }
    }

    /** Preserve adopted identity and historical records on rollback. */
    public function down(): void {}
};
