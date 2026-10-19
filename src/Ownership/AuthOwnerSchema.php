<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Illuminate\Database\Schema\Blueprint;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Ownership\Services\OwnershipDatabaseConstraints;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;

/** Creates additive optional owner storage; historical tenant records remain untouched. @internal */
final readonly class AuthOwnerSchema
{
    /** Retain the native database constraint capability. */
    public function __construct(private OwnershipDatabaseConstraints $constraints) {}

    /** Create only missing additive native workflow tables. */
    public function prepare(OwnershipResourceRegistry $resources): void
    {
        foreach (['auth.memberships', 'auth.membership_locks', 'auth.authentication_intents'] as $key) {
            $definition = $resources->get($key);
            if ($definition->ownership->strategy === 'unscoped') {
                continue;
            }
            $model = new $definition->model;
            $schema = $model->getConnection()->getSchemaBuilder();
            if ($schema->hasTable($model->getTable())) {
                continue;
            }
            $schema->create($model->getTable(), static function (Blueprint $table) use ($key): void {
                $table->uuid('id')->primary();
                if ($key === 'auth.memberships') {
                    $table->string('subject_type', 191);
                    $table->string('subject_id', 191);
                    $table->string('status', 32)->default('active');
                    $table->boolean('is_owner')->default(false);
                    $table->unsignedInteger('revision')->default(1);
                } elseif ($key === 'auth.authentication_intents') {
                    $table->string('purpose', 80);
                    $table->string('nonce_hash', 64)->unique();
                    $table->string('session_binding_hash', 64);
                    $table->string('subject_type', 191)->nullable();
                    $table->string('subject_id', 191)->nullable();
                    $table->text('payload')->nullable();
                    $table->timestamp('expires_at');
                    $table->timestamp('consumed_at')->nullable();
                }
                $table->timestamps();
            });
        }
    }

    /** Prepare partitioned RBAC uniqueness while retaining historical rows. */
    public function prepareTeams(OwnershipResourceRegistry $resources): void
    {
        $roleModel = new ($resources->get('auth.roles')->model);
        $schema = $roleModel->getConnection()->getSchemaBuilder();
        foreach ([AuthTables::ModelHasRoles => 'role_id', AuthTables::ModelHasPermissions => 'permission_id'] as $logical => $foreign) {
            $name = AuthTables::get($logical);
            if (! $schema->hasColumn($name, 'owner_scope_key')) {
                $schema->table($name, static fn (Blueprint $table) => $table->string('owner_scope_key', 191)->nullable());
            }
            foreach ($schema->getIndexes($name) as $index) {
                if ($index['primary'] && ! in_array('owner_scope_key', $index['columns'], true)) {
                    $schema->table($name, static fn (Blueprint $table) => $table->dropPrimary($index['name']));
                }
            }
            $columns = ['owner_scope_key', $foreign, 'model_id', 'model_type'];
            $exists = false;
            foreach ($schema->getIndexes($name) as $index) {
                $exists = $exists || ($index['unique'] && $index['columns'] === $columns);
            }
            if (! $exists) {
                $schema->table($name, static fn (Blueprint $table) => $table->unique($columns, 'auth_owner_pivot_'.substr(hash('sha256', $name), 0, 20)));
            }
        }
        foreach (['auth.memberships' => ['owner_scope_key', 'subject_type', 'subject_id'], 'auth.membership_locks' => ['owner_scope_key'], 'auth.roles' => ['owner_scope_key', 'name', 'guard_name']] as $key => $columns) {
            $definition = $resources->get($key);
            if ($definition->ownership->strategy === 'unscoped') {
                continue;
            }
            $model = new $definition->model;
            $schema = $model->getConnection()->getSchemaBuilder();
            $exists = false;
            foreach ($schema->getIndexes($model->getTable()) as $index) {
                $exists = $exists || ($index['unique'] && $index['columns'] === $columns);
                if ($key === 'auth.roles' && $index['unique'] && $index['columns'] === ['name', 'guard_name']) {
                    $schema->table($model->getTable(), static fn (Blueprint $table) => $table->dropUnique($index['name']));
                }
            }
            if (! $exists) {
                $schema->table($model->getTable(), static fn (Blueprint $table) => $table->unique($columns, 'auth_owned_'.substr(hash('sha256', $model->getTable()), 0, 20)));
            }
        }
    }

    /** Reject unmapped historical assignments and cross-partition hierarchy edges before activation. */
    public function verifyTeams(OwnershipResourceRegistry $resources): void
    {
        $role = new ($resources->get('auth.roles')->model);
        $connection = $role->getConnection();
        foreach ([AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions] as $logical) {
            $table = AuthTables::get($logical);
            if ($connection->table($table)->whereNull('owner_scope_key')->exists()) {
                throw new OwnershipConfigurationInvalid('Every RBAC assignment requires its reviewed native owner partition.');
            }
        }
        $roles = $role->getTable();
        if ($connection->table($roles.' as child')->join($roles.' as parent', 'parent.id', '=', 'child.parent_id')
            ->whereColumn('child.owner_scope_key', '!=', 'parent.owner_scope_key')->exists()) {
            throw new OwnershipConfigurationInvalid('Role hierarchy edges must retain one native owner.');
        }
        if ($connection->table(AuthTables::get(AuthTables::ModelHasRoles).' as assignment')
            ->join($roles.' as role', 'role.id', '=', 'assignment.role_id')
            ->whereColumn('assignment.owner_scope_key', '!=', 'role.owner_scope_key')->exists()) {
            throw new OwnershipConfigurationInvalid('Role assignments must retain their canonical role owner.');
        }
    }

    /** Enforce partition validity, immutability and role references on every supported source. */
    public function constrainTeams(OwnershipResourceRegistry $resources): void
    {
        $this->verifyTeams($resources);
        $role = new ($resources->get('auth.roles')->model);
        $connection = $role->getConnection();
        foreach ([AuthTables::ModelHasRoles => 'role_id', AuthTables::ModelHasPermissions => 'permission_id'] as $logical => $foreign) {
            $table = AuthTables::get($logical);
            if ($connection->getDriverName() !== 'sqlite') {
                $connection->getSchemaBuilder()->table($table, static fn (Blueprint $blueprint) => $blueprint->string('owner_scope_key', 191)->nullable(false)->change());
            }
            $this->constraints->protect($connection, $table, ['owner_scope_key', $foreign, 'model_id', 'model_type'], true,
                $foreign === 'role_id' ? $role->getTable() : null, $foreign === 'role_id' ? $foreign : null, $foreign === 'role_id' ? $role->getKeyName() : null);
        }
        $this->constraints->reference($connection, $role->getTable(), 'parent_id', $role->getTable(), $role->getKeyName(), true);
    }
}
