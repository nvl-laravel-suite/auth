<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\RoleHierarchy;
use Nvl\Auth\Tests\Fixtures\SecurityRace;
use Nvl\Auth\Tests\Fixtures\TestUser;

it('re-reads the ancestor chain so a parent committed after the caller loaded its roles cannot close a cycle', function (): void {
    $actor = $this->user('rbac.cycle@example.test');
    $first = app(AuthRoles::class)->create($actor, ['name' => 'cycle-first', 'priority' => 10, 'permissions' => []]);
    $second = app(AuthRoles::class)->create($actor, ['name' => 'cycle-second', 'priority' => 10, 'permissions' => []]);
    $staleSecond = Role::query()->findOrFail($second->id);
    Role::query()->whereKey($second->id)->update(['parent_id' => $first->id]);

    expect(fn () => DB::transaction(fn () => app(RoleHierarchy::class)->assertParentAllowed($first, $staleSecond)))
        ->toThrow(AuthException::class, 'Role hierarchy cycles are not allowed.');
});

it('admits only one of two concurrent parent changes that together would close a cycle', function (): void {
    $actor = $this->user('rbac.race@example.test');
    $roles = [];
    foreach (['race-x', 'race-p', 'race-y', 'race-q'] as $name) {
        $roles[$name] = app(AuthRoles::class)->create($actor, ['name' => $name, 'priority' => 10, 'permissions' => []])->id;
    }
    Role::query()->whereKey($roles['race-p'])->update(['parent_id' => $roles['race-y']]);
    Role::query()->whereKey($roles['race-q'])->update(['parent_id' => $roles['race-x']]);
    $actorId = $actor->getKey();
    $table = (new Role)->getTable();
    $worker = static function (string $name, string $role, string $parent) use ($actorId, $table): array {
        DB::listen(static function ($query) use ($table): void {
            if (str_starts_with(strtolower($query->sql), 'select') && str_contains($query->sql, $table)) {
                usleep(100000);
            }
        });
        app(AuthRoles::class)->update(TestUser::query()->findOrFail($actorId), $role, ['name' => $name, 'parentId' => $parent, 'priority' => 10, 'permissions' => []]);

        return [];
    };
    $results = SecurityRace::run([
        static fn (): array => $worker('race-x', $roles['race-x'], $roles['race-p']),
        static fn (): array => $worker('race-y', $roles['race-y'], $roles['race-q']),
    ]);
    $parents = Role::query()->whereIn('id', array_values($roles))->pluck('parent_id', 'id')->all();
    $cursor = $roles['race-x'];
    $steps = 0;
    while (($cursor = $parents[$cursor] ?? null) !== null && $steps < 8) {
        $steps++;
    }

    expect(count(array_filter(array_column($results, 'ok'))))->toBe(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and($steps)->toBeLessThan(8);
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed process race requires MySQL/MariaDB/PostgreSQL.');
