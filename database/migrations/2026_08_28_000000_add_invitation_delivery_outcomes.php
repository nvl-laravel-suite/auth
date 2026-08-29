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
    private const COLUMNS = [
        'current_delivery_message_id',
        'delivery_status',
        'delivery_attempted_at',
        'delivered_at',
        'delivery_failed_at',
        'delivery_failure_code',
    ];

    private const STATUS_INDEX = 'nvl_auth_invitations_delivery_status_index';

    /**
     * Add dedicated invitation delivery outcome state.
     */
    public function up(): void
    {
        $schema = Schema::connection($this->connectionName());

        if (! $schema->hasTable(AuthTables::Invitations)) {
            return;
        }

        foreach (self::COLUMNS as $column) {
            if ($schema->hasColumn(AuthTables::Invitations, $column)) {
                continue;
            }

            $schema->table(AuthTables::Invitations, function (Blueprint $table) use ($column): void {
                match ($column) {
                    'current_delivery_message_id' => $table->string($column, 191)->nullable(),
                    'delivery_status' => $table->string($column, 32)->nullable(),
                    'delivery_failure_code' => $table->string($column, 120)->nullable(),
                    default => $table->timestampTz($column)->nullable(),
                };
            });
        }

        if (! $schema->hasIndex(AuthTables::Invitations, self::STATUS_INDEX)) {
            $schema->table(AuthTables::Invitations, function (Blueprint $table): void {
                $table->index(
                    ['delivery_status', 'delivery_attempted_at'],
                    self::STATUS_INDEX,
                );
            });
        }
    }

    /**
     * Remove the unreleased delivery outcome projection.
     */
    public function down(): void
    {
        $schema = Schema::connection($this->connectionName());

        if (! $schema->hasTable(AuthTables::Invitations)) {
            return;
        }

        if ($schema->hasIndex(AuthTables::Invitations, self::STATUS_INDEX)) {
            $schema->table(AuthTables::Invitations, function (Blueprint $table): void {
                $table->dropIndex(self::STATUS_INDEX);
            });
        }

        foreach (array_reverse(self::COLUMNS) as $column) {
            if (! $schema->hasColumn(AuthTables::Invitations, $column)) {
                continue;
            }

            $schema->table(AuthTables::Invitations, function (Blueprint $table) use ($column): void {
                $table->dropColumn($column);
            });
        }
    }

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
