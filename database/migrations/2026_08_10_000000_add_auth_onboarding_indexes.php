<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthSchemaMigration;

return new class extends Migration implements AuthSchemaMigration
{
    /** Add queryable invitation context and compound challenge credentials. */
    public function up(): void
    {
        $schema = Schema::connection($this->connectionName());

        if ($schema->hasTable('nvl_auth_invitations')
            && ! $schema->hasColumn('nvl_auth_invitations', 'context_hash')) {
            $schema->table('nvl_auth_invitations', function (Blueprint $table): void {
                $table->char('context_hash', 64)->nullable()->index();
            });
        }

        if ($schema->hasTable('nvl_auth_challenges')
            && ! $schema->hasColumn('nvl_auth_challenges', 'secondary_secret_hash')) {
            $schema->table('nvl_auth_challenges', function (Blueprint $table): void {
                $table->char('secondary_secret_hash', 64)->nullable()->unique();
            });
        }
    }

    /** Remove the additive onboarding columns. */
    public function down(): void
    {
        $schema = Schema::connection($this->connectionName());

        if ($schema->hasTable('nvl_auth_challenges')
            && $schema->hasColumn('nvl_auth_challenges', 'secondary_secret_hash')) {
            $schema->table('nvl_auth_challenges', function (Blueprint $table): void {
                $table->dropUnique(['secondary_secret_hash']);
                $table->dropColumn('secondary_secret_hash');
            });
        }

        if ($schema->hasTable('nvl_auth_invitations')
            && $schema->hasColumn('nvl_auth_invitations', 'context_hash')) {
            $schema->table('nvl_auth_invitations', function (Blueprint $table): void {
                $table->dropIndex(['context_hash']);
                $table->dropColumn('context_hash');
            });
        }
    }

    /** Resolve the package's optional operational connection. */
    private function connectionName(): ?string
    {
        $connection = Config::get('nvl-auth.connection');

        return is_string($connection) && trim($connection) !== ''
            ? trim($connection)
            : null;
    }
};
