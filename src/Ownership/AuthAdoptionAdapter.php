<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Illuminate\Database\Eloquent\Model;
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
    ) {}

    /** @return list<string> */
    public function resources(): array
    {
        return array_keys(array_filter($this->resources->all(), static fn ($resource): bool => $resource->family === 'auth' && $resource->ownership->strategy !== 'unscoped'));
    }

    /** Resolve a fixed package-owned source for reviewed pre-target identities. */
    public function sourceFor(string $resource): Model
    {
        return new ($this->resources->get($resource)->model);
    }

    /** Reject table spoofing and unknown metadata before staging any historical record. */
    public function validateAssignment(OwnershipMapping $assignment): void
    {
        $source = $this->sourceFor($assignment->resource);
        if ($assignment->metadata !== []) {
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
                $nativeOwner = $definition->ownership->foreignKey === null ? null : ($row->{$definition->ownership->foreignKey} ?? null);
                if ($nativeOwner !== null && ((! is_int($nativeOwner) && ! is_string($nativeOwner)) || (string) $nativeOwner !== $owner?->key)) {
                    throw new OwnershipConfigurationInvalid('Auth adoption cannot relabel an existing native primary owner.');
                }
                $attributes = [];
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

    /** Verify persisted partitions and the complete canonical domain graph. */
    public function verify(OwnershipAdoptionPlan $plan): OwnershipVerification
    {
        foreach ($this->resources() as $key) {
            $this->schema->verify($key);
        }

        $this->nativeSchema->verifyTeams($this->resources);

        return new OwnershipVerification([]);
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
