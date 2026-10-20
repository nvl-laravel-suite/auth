<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Connection;
use Nvl\Support\Ownership\Contracts\OwnershipMaintenanceState;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;
use Nvl\Support\Ownership\Services\PersistedOwnershipStorage;

/** Prevents mutable flags or a cold unscoped boot from declassifying adopted Auth storage. @internal */
final class AuthOwnershipState
{
    private const string ColumnMetadataCatalog = 'information_schema.columns';

    /** Create a request-scoped guard over immutable declarations and actual source identities. */
    public function __construct(
        private readonly OwnershipResourceRegistry $resources,
        private readonly PersistedOwnershipStorage $storage,
        private readonly OwnershipMaintenanceState $maintenance,
    ) {}

    /** Validate immutable native selection without querying storage for metadata-only operations. */
    public function configured(): bool
    {
        if ($this->maintenance->active()) {
            throw new OwnershipViolation('Ordinary Auth operations are unavailable inside adoption callbacks.');
        }
        $compiled = $this->resources->get('auth.roles')->ownership->strategy !== 'unscoped';
        if (config('nvl-auth.ownership.scoped') !== $compiled
            || ($compiled && config('nvl-ownership.enabled') !== true)) {
            throw new OwnershipConfigurationInvalid('Auth ownership selection or its enforcing runtime changed.');
        }

        if ($compiled && (($this->resources->get('auth.memberships')->ownership->strategy !== 'unscoped')
            !== (config('nvl-auth.features.memberships.enabled') === true))) {
            throw new OwnershipConfigurationInvalid('The adopted Auth membership adapter cannot be changed by a runtime feature flag.');
        }

        return $compiled;
    }

    /** Require an enforcing native graph or prove the actual Auth sources have never been partitioned. */
    public function native(): bool
    {
        if ($this->configured()) {
            return true;
        }
        $sources = [];
        foreach ($this->resources->all() as $resource) {
            if ($resource->family !== 'auth') {
                continue;
            }
            $model = new $resource->model;
            $connection = $model->getConnection();
            $source = spl_object_id($connection);
            $sources[$source]['connection'] = $connection;
            $sources[$source]['tables'][] = $model->getTable();
        }
        foreach ($sources as $source) {
            $connection = $source['connection'];
            $tables = array_values(array_unique($source['tables']));
            $probe = $this->storage->probe($connection);
            foreach ($probe['markers'] as $marker) {
                if (! is_string($marker->resource) || str_starts_with($marker->resource, 'auth.')) {
                    throw new OwnershipConfigurationInvalid('Persisted Auth ownership requires its native deployment configuration.');
                }
            }
            $this->assertNoPartitions($connection, $tables);
        }

        return false;
    }

    /** Inspect the complete declared Auth source in one catalog query per schema.
     * @param  list<string>  $tables
     */
    private function assertNoPartitions(Connection $connection, array $tables): void
    {
        $schemas = [];
        foreach ($tables as $table) {
            [$namespace, $name] = $connection->getSchemaBuilder()->parseSchemaAndTable($table, true);
            $namespace ??= $connection->getDriverName() === 'sqlite' ? 'main' : $connection->getDatabaseName();
            $schemas[$namespace][] = $connection->getTablePrefix().$name;
        }
        foreach ($schemas as $namespace => $names) {
            if ($connection->getDriverName() === 'sqlite') {
                $catalog = $namespace.'.sqlite_master';
                $partitioned = $connection->table($catalog)->useWritePdo()->where('type', 'table')->whereIn('name', $names)->where('sql', 'like', '%owner_scope_key%')->exists();
            } else {
                $partitioned = $connection->table(self::ColumnMetadataCatalog)->useWritePdo()->where('table_schema', $namespace)->whereIn('table_name', $names)->where('column_name', 'owner_scope_key')->exists();
            }
            if ($partitioned) {
                throw new OwnershipConfigurationInvalid('Physical Auth ownership requires its native deployment configuration.');
            }
        }
    }
}
