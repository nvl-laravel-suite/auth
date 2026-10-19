<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Ownership\Services\OwnershipDatabaseConstraints;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Tenancy\Definitions\Tables\TenancyTables;
use Throwable;

/** Memoizes adopted permission storage readiness for one request or job scope. */
final class PermissionStorageReadiness
{
    private ?bool $teams = null;

    private ?AuthException $failure = null;

    private bool $awaitingTenantActivation = false;

    /** Retain live configuration and the package role model boundary. */
    public function __construct(private readonly Repository $configuration, private readonly AuthModelRegistry $models, private readonly Container $container) {}

    /** Recheck transitional readiness until the coordinator publishes active Auth storage. */
    public function invalidate(): void
    {
        $this->teams = null;
        $this->failure = null;
        $this->awaitingTenantActivation = true;
    }

    /** Recheck live RBAC references and immutable pivots at every native scope entry. */
    public function assertOwnerTeams(): void
    {
        $this->container->make(OwnershipReadiness::class)->assertActive('auth.roles');
        $class = $this->models->roleClass();
        $role = new $class;
        $connection = $role->getConnection();
        $constraints = $this->container->make(OwnershipDatabaseConstraints::class);
        foreach (['model_has_roles', 'model_has_permissions'] as $key) {
            $table = $this->configuration->get('permission.table_names.'.$key);
            if (! is_string($table)) {
                throw AuthException::invalidConfiguration('Native RBAC requires canonical pivot table metadata.');
            }
            $constraints->assertProtected($connection, $table);
        }
        $constraints->assertReference($connection, $role->getTable(), 'parent_id', $role->getTable(), $role->getKeyName());
    }

    /** Initialize team state only after adopted storage can be verified. */
    public function initialize(): bool
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
        if ($this->teams !== null) {
            return $this->teams;
        }
        try {
            $roleClass = $this->models->roleClass();
            $connection = (new $roleClass)->getConnection();
            $schema = $connection->getSchemaBuilder();
            $tables = $this->configuration->get('permission.table_names', []);
            if (! is_array($tables) || $tables === []) {
                throw AuthException::invalidConfiguration('Permission storage readiness requires configured tables.');
            }
            foreach ($tables as $table) {
                if (! is_string($table) || ! $schema->hasTable($table)) {
                    throw AuthException::invalidConfiguration('Permission storage readiness requires every adopted table.');
                }
            }
            $teams = false;
            if ($this->configuration->get('nvl-auth.ownership.scoped') === true) {
                $this->container->make(OwnershipReadiness::class)->assertActive('auth.roles');
                foreach (['roles', 'model_has_roles', 'model_has_permissions'] as $key) {
                    if (! $schema->hasColumn($tables[$key], 'owner_scope_key')) {
                        throw AuthException::invalidConfiguration('Owner teams require their native partition columns.');
                    }
                }
                $teams = true;
            }

            if ($this->configuration->get('nvl-tenancy.enabled') === true) {
                $stateTable = TenancyTables::get(TenancyTables::InstallationState);
                if (! $schema->hasTable($stateTable)) {
                    throw AuthException::invalidConfiguration('Tenant permission storage readiness requires installation state.');
                }
                $teams = $connection->table($stateTable)->where('resource', 'auth.roles')->where('state', 'active')->exists();
            }
            if ($teams || ! $this->awaitingTenantActivation) {
                $this->teams = $teams;
                $this->awaitingTenantActivation = false;
            }
            $this->configuration->set('permission.teams', $teams);

            return $teams;
        } catch (Throwable) {
            $this->failure = AuthException::invalidConfiguration('Adopted Auth permission storage readiness could not be established.');
            throw $this->failure;
        }
    }
}
