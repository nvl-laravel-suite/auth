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
     * Add the Auth delivery correlation columns introduced after v1.0.1.
     */
    public function up(): void
    {
        $schema = Schema::connection($this->connectionName());

        if ($schema->hasTable(AuthTables::Invitations)) {
            if (! $schema->hasColumn(AuthTables::Invitations, 'context_hash')) {
                $schema->table(AuthTables::Invitations, function (Blueprint $table): void {
                    $table->char('context_hash', 64)->nullable();
                });
            }

            if (! $schema->hasIndex(
                AuthTables::Invitations,
                'nvl_auth_invitations_context_hash_index',
            )) {
                $schema->table(AuthTables::Invitations, function (Blueprint $table): void {
                    $table->index(
                        'context_hash',
                        'nvl_auth_invitations_context_hash_index',
                    );
                });
            }
        }

        if ($schema->hasTable(AuthTables::Challenges)) {
            if (! $schema->hasColumn(AuthTables::Challenges, 'secondary_secret_hash')) {
                $schema->table(AuthTables::Challenges, function (Blueprint $table): void {
                    $table->char('secondary_secret_hash', 64)->nullable();
                });
            }

            if (! $schema->hasIndex(
                AuthTables::Challenges,
                'nvl_auth_challenges_secondary_secret_hash_unique',
            )) {
                $schema->table(AuthTables::Challenges, function (Blueprint $table): void {
                    $table->unique(
                        'secondary_secret_hash',
                        'nvl_auth_challenges_secondary_secret_hash_unique',
                    );
                });
            }
        }
    }

    /**
     * Preserve active invitation and challenge security evidence on rollback.
     */
    public function down(): void {}

    /**
     * Resolve the configured Auth connection.
     */
    private function connectionName(): ?string
    {
        $connection = Config::get('nvl-auth.connection');

        return is_string($connection) && trim($connection) !== ''
            ? trim($connection)
            : null;
    }
};
