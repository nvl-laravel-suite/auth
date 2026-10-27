<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Ownership\AuthOwnerSchema;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\Tests\NativeOwnerConcurrencyTestCase;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;

uses(NativeOwnerConcurrencyTestCase::class);

it('preserves pivot foreign keys and owner uniqueness when replacing primary keys', function (bool $existingIndex): void {
    $scenario = new AuthOwnerScenario;
    $actor = $this->user('schema@example.test');
    $role = $scenario->run($scenario->a(), fn (): Role => Role::query()->create(['name' => 'schema', 'guard_name' => 'web']));
    $permission = Permission::query()->create(['name' => 'schema.read', 'guard_name' => 'web']);
    $schema = $role->getConnection()->getSchemaBuilder();
    $pivots = [
        'model_has_roles' => ['role_id', $role],
        'model_has_permissions' => ['permission_id', $permission],
    ];

    foreach ($pivots as $logical => [$foreign, $reference]) {
        $name = 'custom_'.str_repeat('pivot_', 5).$logical;
        $schema->create($name, static function (Blueprint $table) use ($foreign, $reference, $existingIndex): void {
            $table->uuid($foreign);
            $table->foreign($foreign, 'custom_fk_'.substr(hash('sha256', $foreign), 0, 12))
                ->references($reference->getKeyName())->on($reference->getTable())->cascadeOnDelete();
            $table->uuid('model_id');
            $table->string('model_type', 160);
            $table->primary([$foreign, 'model_id', 'model_type'], 'legacy_pk_'.substr(hash('sha256', $foreign), 0, 12));
            if ($existingIndex) {
                $table->index([$foreign, 'model_id'], 'reviewed_fk_'.substr(hash('sha256', $foreign), 0, 12));
            }
        });
        config(['nvl-auth.tables.'.$logical => $name]);
    }

    $resources = app(OwnershipResourceRegistry::class);
    $migration = app(AuthOwnerSchema::class);
    $migration->prepareTeams($resources);
    $migration->prepareTeams($resources);

    foreach ($pivots as $logical => [$foreign, $reference]) {
        $name = AuthTables::get($logical);
        $indexes = $schema->getIndexes($name);
        $leading = array_values(array_filter($indexes, static fn (array $index): bool => ! $index['primary'] && $index['columns'][0] === $foreign));
        if (in_array($role->getConnection()->getDriverName(), ['mysql', 'mariadb'], true) || $existingIndex) {
            expect($leading)->toHaveCount(1);
        }
        expect(array_column($schema->getForeignKeys($name), 'columns'))->toContain([$foreign])
            ->and(array_any($indexes, static fn (array $index): bool => $index['unique'] && $index['columns'] === ['owner_scope_key', $foreign, 'model_id', 'model_type']))->toBeTrue();
        foreach ($indexes as $index) {
            expect(strlen($index['name']))->toBeLessThanOrEqual(63);
        }

        $attributes = ['owner_scope_key' => $scenario->a()->scopeKey(), $foreign => $reference->getKey(), 'model_id' => $actor->getAuthIdentifier(), 'model_type' => $actor->getMorphClass()];
        DB::table($name)->insert($attributes);
        expect(fn () => DB::table($name)->insert($attributes))->toThrow(QueryException::class)
            ->and(fn () => DB::table($name)->insert([...$attributes, $foreign => (string) Str::uuid()]))->toThrow(QueryException::class);
    }
})->with(['create foreign support' => false, 'reuse existing support' => true]);
