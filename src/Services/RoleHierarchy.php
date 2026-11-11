<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Support\Collection;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;

/**
 * Validates role parent changes and renders a deterministic hierarchy.
 *
 * @internal
 */
final class RoleHierarchy
{
    /**
     * Require a parent assignment to remain acyclic and in the same guard.
     *
     * Must run inside the transaction that writes the parent: every role of the guard is
     * locked in key order and the ancestor chain is read from those locked rows, so two
     * concurrent parent changes cannot each pass against the other's uncommitted state.
     */
    public function assertParentAllowed(Role $role, ?Role $parent): void
    {
        if ($parent === null) {
            return;
        }
        if ($parent->id === $role->id || $parent->guard_name !== $role->guard_name) {
            throw new AuthException('invalid_role_parent', 'The selected role parent is invalid.', 422);
        }
        $parents = [];
        foreach ($role->newQuery()->where('guard_name', $role->guard_name)->orderBy($role->getKeyName())->lockForUpdate()->get(['id', 'parent_id']) as $locked) {
            $parents[$locked->id] = $locked->parent_id;
        }
        $ancestor = $parent->id;
        $visited = [];
        while (($next = $parents[$ancestor] ?? null) !== null) {
            if (isset($visited[$ancestor])) {
                throw new AuthException('role_hierarchy_cycle', 'The persisted role hierarchy contains a cycle.', 422);
            }
            $visited[$ancestor] = true;
            if ($next === $role->id) {
                throw new AuthException('role_hierarchy_cycle', 'Role hierarchy cycles are not allowed.', 422);
            }
            $ancestor = $next;
        }
    }

    /**
     * Build nested hierarchy nodes from one complete role collection.
     *
     * @param  Collection<int, Role>  $roles
     * @return list<array{id: string, name: string, display_name: string|null, priority: int, user_count: int, children: list<mixed>}>
     */
    public function tree(Collection $roles): array
    {
        $grouped = $roles->groupBy(static fn (Role $role): string => $role->parent_id ?? 'root');

        return $this->children($grouped, 'root', []);
    }

    /**
     * Build one hierarchy level while protecting against corrupt persisted cycles.
     *
     * @param  Collection<string, Collection<int, Role>>  $grouped
     * @param  array<string, true>  $visited
     * @return list<array{id: string, name: string, display_name: string|null, priority: int, user_count: int, children: list<mixed>}>
     */
    private function children(Collection $grouped, string $parent, array $visited): array
    {
        $nodes = [];
        foreach ($grouped->get($parent, collect()) as $role) {
            if (isset($visited[$role->id])) {
                continue;
            }
            $branch = [...$visited, $role->id => true];
            $nodes[] = ['id' => $role->id, 'name' => $role->name, 'display_name' => $role->display_name, 'priority' => $role->priority, 'user_count' => (int) ($role->users_count ?? 0), 'children' => $this->children($grouped, $role->id, $branch)];
        }

        return $nodes;
    }
}
