<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use Nvl\Auth\Models\Challenge;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;
use Nvl\Support\Ownership\Services\OwnershipScope;

/**
 * Restricts credential challenge workflows to central identity rows without granting central execution.
 * It exposes no owned-resource runner or arbitrary persistence callback.
 *
 * @internal
 */
final readonly class AuthIdentityChallenges
{
    public function __construct(private OwnershipReadiness $readiness) {}

    /** @return Builder<Challenge> */
    public function query(): Builder
    {
        if (config('nvl-auth.ownership.scoped') !== true) {
            return Challenge::query();
        }
        $this->readiness->assertActive('auth.challenges');

        return Challenge::query()->withoutGlobalScope(OwnershipScope::class)->where('owner_scope_key', 'central')->whereNull('owner_reference');
    }

    /** Persist a global credential challenge, never a row in an owner partition.
     * @param  array<string,mixed>  $attributes
     */
    public function create(array $attributes): Challenge
    {
        if (config('nvl-auth.ownership.scoped') !== true) {
            return Challenge::query()->create($attributes);
        }
        $this->readiness->assertActive('auth.challenges');
        $model = new Challenge;
        $model->forceFill([...$attributes, 'id' => (string) Str::uuid(), 'owner_scope_key' => 'central', 'owner_reference' => null, 'created_at' => now(), 'updated_at' => now()]);
        $model->getConnection()->table($model->getTable())->insert($model->getAttributes());

        return $this->query()->whereKey($model->getKey())->firstOrFail();
    }

    /** Apply only challenge state changes to a reloaded central identity record. */
    public function save(Challenge $challenge): bool
    {
        if (config('nvl-auth.ownership.scoped') !== true) {
            return $challenge->save();
        }
        $this->readiness->assertActive('auth.challenges');
        $changes = $challenge->getDirty();
        $allowed = ['active_key', 'attempts', 'consumed_at', 'revoked_at', 'payload', 'updated_at'];
        if (! $challenge->exists || array_diff(array_keys($changes), $allowed) !== []
            || $challenge->getTable() !== (new Challenge)->getTable() || $challenge->getConnection() !== (new Challenge)->getConnection()) {
            throw new OwnershipViolation('Credential challenge state cannot change its identity or ownership.');
        }

        return $challenge->getConnection()->transaction(function () use ($challenge, $changes): bool {
            $query = $this->query()->whereKey($challenge->getKey());
            if (! $query->lockForUpdate()->first() instanceof Challenge) {
                throw new OwnershipViolation('The global credential challenge is unavailable.');
            }
            $query->toBase()->update([...$changes, 'updated_at' => now()]);
            $challenge->syncOriginal();

            return true;
        }, 3);
    }
}
