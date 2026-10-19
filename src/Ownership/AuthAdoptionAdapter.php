<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Compatibility\LegacyAuthAdoptionSource;
use Nvl\Ownership\Contracts\OwnershipAdoptionAdapter;
use Nvl\Ownership\Contracts\OwnershipAdoptionMetadataValidator;
use Nvl\Ownership\Contracts\OwnershipAdoptionSource;
use Nvl\Ownership\Services\OwnershipAdoptionStore;
use Nvl\Ownership\Services\OwnershipSchema;
use Nvl\Ownership\ValueObjects\OwnershipAdoptionPlan;
use Nvl\Ownership\ValueObjects\OwnershipBackfillResult;
use Nvl\Ownership\ValueObjects\OwnershipMapping;
use Nvl\Ownership\ValueObjects\OwnershipVerification;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;
use stdClass;

/**
 * Adopts exact reviewed Auth records without guessing primary owners from associations.
 *
 * @internal
 */
final readonly class AuthAdoptionAdapter implements OwnershipAdoptionAdapter, OwnershipAdoptionMetadataValidator, OwnershipAdoptionSource
{
    /** Retain the canonical services and immutable inputs for this workflow. */
    public function __construct(
        private OwnershipResourceRegistry $resources,
        private OwnershipAdoptionStore $mappings,
        private OwnershipSchema $schema,
        private AuthOwnerSchema $nativeSchema,
        private LegacyAuthAdoptionSource $sources,
    ) {}

    /** @return list<string> */
    public function resources(): array
    {
        return array_keys(array_filter($this->resources->all(), static fn ($resource): bool => $resource->family === 'auth' && $resource->ownership->strategy !== 'unscoped'));
    }

    /** Resolve a fixed package-owned source for reviewed pre-target identities. */
    public function sourceFor(string $resource): Model
    {
        return $this->sources->sourceFor($resource);
    }

    /** Reject table spoofing and unknown metadata before staging any historical record. */
    public function validateAssignment(OwnershipMapping $assignment): void
    {
        $source = $this->sourceFor($assignment->resource);
        if ($assignment->metadata !== [] && (count($assignment->metadata) !== 2 || ($assignment->metadata['legacy_source_table'] ?? null) !== $source->getTable() || ($assignment->metadata['legacy_source_key'] ?? null) !== $source->getKeyName())) {
            throw new OwnershipConfigurationInvalid('Auth mapping metadata must name its exact fixed historical source.');
        }
    }

    /** Prepare additive partitions and native membership and RBAC identities. */
    public function prepare(OwnershipAdoptionPlan $plan): void
    {
        $this->nativeSchema->prepare($this->resources);
        foreach ($this->resources() as $key) {
            $this->schema->prepare($key);
        }
        $this->nativeSchema->prepareTeams($this->resources);
    }

    /** Backfill bounded actual records from explicit immutable per-record mappings. */
    public function backfill(OwnershipAdoptionPlan $plan, ?string $cursor, int $limit): OwnershipBackfillResult
    {
        $processed = 0;
        do {
            $result = $this->backfillResource($plan, $cursor, $limit - $processed);
            $processed += $result->processed;
            $cursor = $result->nextCursor;
        } while ($cursor !== null && $processed < $limit);

        return new OwnershipBackfillResult($cursor, $processed);
    }

    /** Consume at most one resource page without counting empty tables as progress. */
    private function backfillResource(OwnershipAdoptionPlan $plan, ?string $cursor, int $limit): OwnershipBackfillResult
    {
        $parts = $cursor === null ? ['0', ''] : explode(':', $cursor, 2);
        if (count($parts) !== 2 || preg_match('/^[0-9]+$/D', $parts[0]) !== 1) {
            throw new OwnershipConfigurationInvalid('Invalid Auth adoption cursor.');
        }
        $keys = $this->resources();
        $position = (int) $parts[0];
        $key = $keys[$position] ?? throw new OwnershipConfigurationInvalid('Invalid Auth adoption resource.');
        $definition = $this->resources->get($key);
        $model = new $definition->model;
        $connection = $model->getConnection();
        $source = $this->sourceFor($key);
        $rows = $connection->table($source->getTable())->when($parts[1] !== '', static fn ($query) => $query->where($source->getKeyName(), '>', $parts[1]))->orderBy($source->getKeyName())->limit($limit)->get();
        $last = '';
        $connection->transaction(function () use ($rows, $key, $plan, $definition, $model, $source, $connection, &$last): void {
            foreach ($rows as $row) {
                $row->id = $row->{$source->getKeyName()};
                if (! is_string($row->id)) {
                    throw new OwnershipConfigurationInvalid('Auth adoption requires canonical UUID records.');
                }
                $mapping = $this->mappings->forRecord($plan, $key, $row->id);
                $owner = $mapping->owner;
                if (isset($row->tenant_id) && $mapping->legacyTenantId !== $row->tenant_id) {
                    throw new OwnershipConfigurationInvalid('Reviewed Auth mappings must preserve the original tenant identity.');
                }
                $nativeOwner = $definition->ownership->foreignKey === null ? null : ($row->{$definition->ownership->foreignKey} ?? null);
                if ($nativeOwner !== null && ((! is_int($nativeOwner) && ! is_string($nativeOwner)) || (string) $nativeOwner !== $owner?->key)) {
                    throw new OwnershipConfigurationInvalid('Auth adoption cannot relabel an existing native primary owner.');
                }
                $attributes = $this->historicalAttributes($key, $source, $model, $row);
                $attributes += ['owner_scope_key' => $owner?->scopeKey() ?? 'central'];
                $ownership = $definition->ownership;
                if ($ownership->strategy === 'captured') {
                    $attributes['owner_reference'] = $owner === null ? null : json_encode($owner->toArray(), JSON_THROW_ON_ERROR);
                } elseif ($ownership->strategy === 'column') {
                    $attributes[$ownership->foreignKey ?? throw new OwnershipConfigurationInvalid] = $owner?->key;
                } elseif ($ownership->strategy === 'pivot' && $owner !== null) {
                    $connection->table($ownership->table ?? throw new OwnershipConfigurationInvalid)->insertOrIgnore([
                        $ownership->resourceKey ?? throw new OwnershipConfigurationInvalid => $row->id,
                        $ownership->ownerKey ?? throw new OwnershipConfigurationInvalid => $owner->key,
                        'owner_scope_key' => $owner->scopeKey(),
                    ]);
                }
                $connection->table($model->getTable())->updateOrInsert(['id' => $row->id], $attributes);
                $last = $row->id;
            }
        });
        $next = $rows->count() === $limit ? $position.':'.$last : ($position + 1 < count($keys) ? ($position + 1).':' : null);

        return new OwnershipBackfillResult($next, $rows->count());
    }

    /** Copy only declared native fields; pending legacy authentication must drain before cutover.
     * @return array<string,mixed>
     */
    private function historicalAttributes(string $key, Model $source, Model $target, stdClass $row): array
    {
        if ($source->getTable() === $target->getTable()) {
            return [];
        }
        if ($key === 'auth.authentication_intents' && $row->consumed_at === null && $row->expires_at > now()->toDateTimeString()) {
            throw new OwnershipConfigurationInvalid('Pending historical authentication intents must drain or expire before ownership cutover.');
        }
        $attributes = [];
        foreach ($target->getConnection()->getSchemaBuilder()->getColumnListing($target->getTable()) as $column) {
            if (! in_array($column, ['id', 'owner_scope_key', 'owner_reference'], true) && property_exists($row, $column)) {
                $attributes[$column] = $row->{$column};
            }
        }
        $existing = $target->getConnection()->table($target->getTable())->where('id', $row->id)->first();
        if ($existing !== null) {
            foreach ($attributes as $column => $value) {
                if ($existing->{$column} !== $value) {
                    throw new OwnershipConfigurationInvalid('Historical Auth staging cannot overwrite a changed native record.');
                }
            }
        }

        return $attributes;
    }

    /** Verify persisted partitions and the complete canonical domain graph. */
    public function verify(OwnershipAdoptionPlan $plan): OwnershipVerification
    {
        foreach ($this->resources() as $key) {
            $this->schema->verify($key);
        }

        $this->verifyHistoricalCopies();
        $this->nativeSchema->verifyTeams($this->resources);

        return new OwnershipVerification([]);
    }

    /** Compare every historical authorization fact and every staged identity in both directions. */
    private function verifyHistoricalCopies(): void
    {
        foreach ($this->resources() as $key) {
            $source = $this->sourceFor($key);
            $target = new ($this->resources->get($key)->model);
            if ($source->getTable() === $target->getTable()) {
                continue;
            }
            $connection = $target->getConnection();
            if ($connection->table($source->getTable())->count() !== $connection->table($target->getTable())->count()) {
                throw new OwnershipConfigurationInvalid('Historical Auth identities were lost or new identities appeared during staging.');
            }
            foreach ($connection->table($source->getTable())->orderBy($source->getKeyName())->cursor() as $row) {
                $row->id = $row->{$source->getKeyName()};
                if (! $connection->table($target->getTable())->where('id', $row->id)->exists()) {
                    throw new OwnershipConfigurationInvalid('A historical Auth identity is missing from its native target.');
                }
                $this->historicalAttributes($key, $source, $target, $row);
            }
        }
    }

    /** Constrain every native parent and scope edge before activation. */
    public function activate(OwnershipAdoptionPlan $plan): void
    {
        foreach ($this->resources() as $key) {
            $this->schema->constrain($key);
        }
        $this->nativeSchema->constrainTeams($this->resources);
    }
}
