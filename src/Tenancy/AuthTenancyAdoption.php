<?php

declare(strict_types=1);

namespace Nvl\Auth\Tenancy;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Database\Schema\Blueprint;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Models\Role;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantAdoptionAdapter;
use Nvl\Tenancy\Contracts\TenantAdoptionMetadataValidator;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\Exceptions\TenantConfigurationInvalid;
use Nvl\Tenancy\Services\EffectiveTenantConnection;
use Nvl\Tenancy\Services\TenantAdoptionMappings;
use Nvl\Tenancy\ValueObjects\TenantAdoptionPlan;
use Nvl\Tenancy\ValueObjects\TenantAssignment;
use Nvl\Tenancy\ValueObjects\TenantBackfillResult;
use Nvl\Tenancy\ValueObjects\TenantVerification;
use Spatie\Permission\PermissionRegistrar;

/** Owns Auth's reviewed, resumable tenant adoption and final schema cutover. */
final readonly class AuthTenancyAdoption implements TenantAdoptionAdapter, TenantAdoptionMetadataValidator
{
    private const array PHASES = ['memberships', 'roles', 'role_parents', 'grants', 'invitations', 'audits'];

    /** Create the package-owned adoption boundary. */
    public function __construct(
        private Migrator $migrator,
        private AuthTenancyMapping $mapping,
        private TenantAdoptionMappings $mappings,
        private MembershipPrincipalResolver $principals,
        private EffectiveTenantConnection $connections,
        private ConfigRepository $configuration,
        private PermissionRegistrar $registrar,
    ) {}

    /** Validate Auth's exact reviewed mapping metadata before preparation. */
    public function validateAssignment(TenantAssignment $assignment): void
    {
        $this->mapping->validate($assignment);
    }

    /** @return list<string> */
    public function resources(): array
    {
        return [
            'auth.memberships',
            'auth.membership_locks',
            'auth.roles',
            'auth.invitations',
            'auth.tokens',
            'auth.challenges',
            'auth.audits',
            'auth.authentication_intents',
            'auth.permissions',
        ];
    }

    /** Prepare nullable ownership columns and backfill-compatible role keys. */
    public function prepare(TenantAdoptionPlan $plan): void
    {
        $this->assertConnections($plan);
        $path = dirname(__DIR__, 2).'/database/migrations/tenancy';
        $this->migrator->usingConnection($plan->connection, fn () => $this->migrator->run([$path], ['force' => true]));
        $schema = $this->connection($plan)->getSchemaBuilder();

        if ($schema->hasIndex(AuthTables::Roles, 'nvl_auth_roles_name_guard_unique')) {
            $schema->table(AuthTables::Roles, static function (Blueprint $table): void {
                $table->dropUnique('nvl_auth_roles_name_guard_unique');
            });
        }
        if (! $schema->hasIndex(AuthTables::Roles, 'nvl_auth_roles_tenant_name_guard_unique')) {
            $schema->table(AuthTables::Roles, static function (Blueprint $table): void {
                $table->unique(['tenant_id', 'name', 'guard_name'], 'nvl_auth_roles_tenant_name_guard_unique');
            });
        }
        if ($schema->hasIndex(AuthTables::ModelHasPermissions, 'nvl_auth_model_permissions_primary')) {
            $schema->table(AuthTables::ModelHasPermissions, static function (Blueprint $table): void {
                $table->dropPrimary('nvl_auth_model_permissions_primary');
                $table->unique(
                    ['tenant_id', 'permission_id', 'model_id', 'model_type'],
                    'nvl_auth_model_permissions_tenant_unique',
                );
            });
        }
    }

    /** Backfill one bounded reviewed mapping phase and classify legacy mixed ownership. */
    public function backfill(TenantAdoptionPlan $plan, ?string $cursor, int $limit): TenantBackfillResult
    {
        $this->assertConnections($plan);
        [$phase, $after] = $this->cursor($cursor);
        $start = array_search($phase, self::PHASES, true);
        if (! is_int($start)) {
            throw new TenantConfigurationInvalid('The Auth adoption cursor phase is invalid.');
        }

        for ($index = $start; $index < count(self::PHASES); $index++) {
            $current = self::PHASES[$index];
            $resource = match ($current) {
                'memberships', 'grants' => 'auth.memberships',
                'roles', 'role_parents' => 'auth.roles',
                'invitations' => 'auth.invitations',
                'audits' => 'auth.audits',
            };
            $batch = $this->mappings->assignments($plan, $resource, $current === $phase ? $after : null, $limit);
            if ($batch === []) {
                continue;
            }
            $this->connection($plan)->transaction(function () use ($current, $batch, $plan): void {
                foreach ($batch as $assignment) {
                    $this->backfillAssignment($plan, $current, $assignment);
                }
            });
            $last = $batch[array_key_last($batch)];

            return new TenantBackfillResult($current.':'.$last->recordId, count($batch));
        }

        $this->connection($plan)->transaction(fn () => $this->classifyHistoricalRows($plan));

        return new TenantBackfillResult(null, 0);
    }

    /** Verify prepared ownership, reviewed dispositions, and same-tenant RBAC references. */
    public function verify(TenantAdoptionPlan $plan): TenantVerification
    {
        $this->assertConnections($plan);
        $connection = $this->connection($plan);
        $schema = $connection->getSchemaBuilder();
        $errors = [];
        foreach ([AuthTables::TenantMemberships, AuthTables::TenantMembershipLocks, AuthTables::TenantAuthenticationIntents] as $table) {
            if (! $schema->hasTable($table)) {
                $errors[] = $table.'.missing';
            }
        }
        foreach ([AuthTables::Roles, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions] as $table) {
            if (! $schema->hasColumn($table, 'tenant_id')) {
                $errors[] = $table.'.tenant_id';
            }
        }
        foreach ([AuthTables::Invitations, AuthTables::PersonalAccessTokens, AuthTables::Challenges, AuthTables::Audits] as $table) {
            if (! $schema->hasColumns($table, ['tenant_id', 'ownership_key'])) {
                $errors[] = $table.'.ownership';
            }
        }
        if ($schema->hasTable(AuthTables::TenantMemberships)
            && ! $schema->hasIndex(AuthTables::TenantMemberships, ['tenant_id', 'subject_type', 'subject_id'], 'unique')) {
            $errors[] = AuthTables::TenantMemberships.'.identity';
        }
        foreach ([AuthTables::Roles, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions] as $table) {
            if ($schema->hasTable($table) && $connection->table($table)->whereNull('tenant_id')->exists()) {
                $errors[] = $table.'.unmapped';
            }
        }
        if ($schema->hasTable(AuthTables::Invitations)
            && $connection->table(AuthTables::Invitations)->whereNull('tenant_id')->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '>', now())->exists()) {
            $errors[] = AuthTables::Invitations.'.live_unmapped';
        }
        if ($schema->hasTable(AuthTables::PersonalAccessTokens)
            && $connection->table(AuthTables::PersonalAccessTokens)->whereNull('tenant_id')->exists()) {
            $errors[] = AuthTables::PersonalAccessTokens.'.unbound';
        }
        if ($schema->hasTable(AuthTables::TenantMemberships)) {
            foreach ($connection->table(AuthTables::TenantMemberships)->where('status', 'active')->distinct()->pluck('tenant_id') as $tenantId) {
                if (! is_string($tenantId) || ! $connection->table(AuthTables::TenantMemberships)
                    ->where('tenant_id', $tenantId)->where('status', 'active')->where('is_owner', true)->exists()) {
                    $errors[] = AuthTables::TenantMemberships.'.owner_missing';
                    break;
                }
            }
        }
        if ($schema->hasTable(AuthTables::Roles) && $connection->table(AuthTables::Roles.' as child')
            ->join(AuthTables::Roles.' as parent', 'parent.id', '=', 'child.parent_id')
            ->whereColumn('parent.tenant_id', '!=', 'child.tenant_id')->exists()) {
            $errors[] = AuthTables::Roles.'.parent_tenant';
        }
        if ($schema->hasTable(AuthTables::ModelHasRoles) && $connection->table(AuthTables::ModelHasRoles.' as pivot')
            ->join(AuthTables::Roles.' as role', 'role.id', '=', 'pivot.role_id')
            ->whereColumn('role.tenant_id', '!=', 'pivot.tenant_id')->exists()) {
            $errors[] = AuthTables::ModelHasRoles.'.role_tenant';
        }
        foreach ([AuthTables::Invitations, AuthTables::PersonalAccessTokens, AuthTables::Challenges, AuthTables::Audits] as $table) {
            if ($schema->hasTable($table) && $this->hasInvalidOwnership($connection, $table)) {
                $errors[] = $table.'.ownership_invalid';
            }
        }

        return new TenantVerification(array_values(array_unique($errors)));
    }

    /** Install final tenant role and assignment constraints and activate Spatie teams locally. */
    public function activate(TenantAdoptionPlan $plan): void
    {
        $connection = $this->connection($plan);
        $schema = $connection->getSchemaBuilder();
        if (! $this->verify($plan)->passed()) {
            throw new TenantBoundaryViolation('Auth tenant schema did not verify before activation.');
        }

        if (! $schema->hasIndex(AuthTables::Roles, 'nvl_auth_roles_tenant_id_unique')) {
            $schema->table(AuthTables::Roles, static function (Blueprint $table): void {
                $table->unique(['tenant_id', 'id'], 'nvl_auth_roles_tenant_id_unique');
            });
        }
        foreach ([AuthTables::Roles, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions] as $table) {
            $schema->table($table, static function (Blueprint $blueprint): void {
                $blueprint->uuid('tenant_id')->nullable(false)->change();
            });
        }
        $this->replacePivotPrimary($schema, AuthTables::ModelHasRoles, ['tenant_id', 'role_id', 'model_id', 'model_type'], 'nvl_auth_model_roles_primary');
        if ($schema->hasIndex(AuthTables::ModelHasPermissions, 'nvl_auth_model_permissions_tenant_unique')) {
            $schema->table(AuthTables::ModelHasPermissions, static function (Blueprint $table): void {
                $table->dropUnique('nvl_auth_model_permissions_tenant_unique');
            });
        }
        $this->replacePivotPrimary($schema, AuthTables::ModelHasPermissions, ['tenant_id', 'permission_id', 'model_id', 'model_type'], 'nvl_auth_model_permissions_primary');

        $this->configuration->set('permission.teams', true);
        $this->configuration->set('permission.column_names.team_foreign_key', 'tenant_id');
        $this->registrar->initializeCache();
        $this->registrar->forgetCachedPermissions();
        if (! $this->verify($plan)->passed()) {
            throw new TenantBoundaryViolation('Auth tenant schema did not verify after activation.');
        }
    }

    /** Apply one already validated assignment. */
    private function backfillAssignment(TenantAdoptionPlan $plan, string $phase, TenantAssignment $assignment): void
    {
        match ($phase) {
            'memberships' => $this->backfillMembership($assignment),
            'roles' => $this->backfillRole($plan, $assignment),
            'role_parents' => $this->backfillRoleParent($assignment),
            'grants' => $this->backfillGrants($assignment),
            'invitations' => $this->backfillInvitation($assignment),
            'audits' => $this->backfillAudit($assignment),
            default => throw new TenantConfigurationInvalid('The Auth adoption phase is invalid.'),
        };
    }

    /** Create one explicit membership and its retained tenant lock. */
    private function backfillMembership(TenantAssignment $assignment): void
    {
        $metadata = $assignment->metadata;
        $reference = new SubjectReference($metadata['subject_type'], $metadata['subject_id']);
        if ($metadata['status'] === 'active') {
            $this->principals->resolve($reference);
        }
        $connection = $this->connectionForModels();
        $timestamp = now();
        $connection->table(AuthTables::TenantMembershipLocks)->updateOrInsert(
            ['tenant_id' => $assignment->tenantId->value],
            ['created_at' => $timestamp, 'updated_at' => $timestamp],
        );
        $connection->table(AuthTables::TenantMemberships)->updateOrInsert(
            ['id' => $assignment->recordId],
            [
                'tenant_id' => $assignment->tenantId->value,
                'subject_type' => $reference->type,
                'subject_id' => $reference->identifier,
                'status' => $metadata['status'],
                'is_owner' => $metadata['is_owner'],
                'revision' => 1,
                'created_at' => $timestamp,
                'updated_at' => $timestamp,
            ],
        );
    }

    /** Clone one reviewed legacy role and its global permission vocabulary links. */
    private function backfillRole(TenantAdoptionPlan $plan, TenantAssignment $assignment): void
    {
        $connection = $this->connection($plan);
        $sourceId = $assignment->metadata['source_id'];
        $source = $connection->table(AuthTables::Roles)->where('id', $sourceId)->first();
        if ($source === null) {
            throw new TenantBoundaryViolation('A reviewed Auth role source is unavailable.');
        }
        $connection->table(AuthTables::Roles)->updateOrInsert(
            ['id' => $assignment->recordId],
            [
                'tenant_id' => $assignment->tenantId->value,
                'name' => $source->name,
                'guard_name' => $source->guard_name,
                'display_name' => $source->display_name,
                'description' => $source->description,
                'parent_id' => null,
                'priority' => $source->priority,
                'is_system' => $source->is_system,
                'metadata' => $source->metadata,
                'created_at' => $source->created_at,
                'updated_at' => now(),
            ],
        );
        foreach ($connection->table(AuthTables::RoleHasPermissions)->where('role_id', $sourceId)->pluck('permission_id') as $permissionId) {
            $connection->table(AuthTables::RoleHasPermissions)->insertOrIgnore([
                'permission_id' => $permissionId,
                'role_id' => $assignment->recordId,
            ]);
        }
    }

    /** Close the cloned role hierarchy only after every destination role exists. */
    private function backfillRoleParent(TenantAssignment $assignment): void
    {
        $connection = $this->connectionForModels();
        $parentId = $assignment->metadata['parent_destination_id'];
        if ($parentId !== null && ! $connection->table(AuthTables::Roles)
            ->where('id', $parentId)->where('tenant_id', $assignment->tenantId->value)->exists()) {
            throw new TenantBoundaryViolation('A reviewed Auth role parent is outside the destination tenant.');
        }
        $connection->table(AuthTables::Roles)->where('id', $assignment->recordId)->update([
            'parent_id' => $parentId,
            'updated_at' => now(),
        ]);
    }

    /** Write only the membership's explicitly reviewed role and direct-permission grants. */
    private function backfillGrants(TenantAssignment $assignment): void
    {
        $metadata = $assignment->metadata;
        $connection = $this->connectionForModels();
        foreach ($metadata['role_ids'] as $roleId) {
            if (! $connection->table(AuthTables::Roles)->where('id', $roleId)->where('tenant_id', $assignment->tenantId->value)->exists()) {
                throw new TenantBoundaryViolation('A reviewed membership role is outside the destination tenant.');
            }
            $connection->table(AuthTables::ModelHasRoles)->insertOrIgnore([
                'tenant_id' => $assignment->tenantId->value,
                'role_id' => $roleId,
                'model_type' => $metadata['subject_type'],
                'model_id' => $metadata['subject_id'],
            ]);
        }
        foreach ($metadata['permission_ids'] as $permissionId) {
            if (! $connection->table(AuthTables::Permissions)->where('id', $permissionId)->exists()) {
                throw new TenantBoundaryViolation('A reviewed membership permission is unavailable.');
            }
            $connection->table(AuthTables::ModelHasPermissions)->insertOrIgnore([
                'tenant_id' => $assignment->tenantId->value,
                'permission_id' => $permissionId,
                'model_type' => $metadata['subject_type'],
                'model_id' => $metadata['subject_id'],
            ]);
        }
    }

    /** Assign one still-live invitation and canonical reviewed grants. */
    private function backfillInvitation(TenantAssignment $assignment): void
    {
        $query = $this->connectionForModels()->table(AuthTables::Invitations)->where('id', $assignment->recordId)
            ->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '>', now());
        if (! (clone $query)->exists()) {
            throw new TenantBoundaryViolation('Only a live unconsumed invitation may receive reviewed tenant ownership.');
        }
        $query->update([
            'tenant_id' => $assignment->tenantId->value,
            'ownership_key' => 'tenant:'.$assignment->tenantId->value,
            'roles' => json_encode($assignment->metadata['role_ids'], JSON_THROW_ON_ERROR),
            'permissions' => json_encode($assignment->metadata['permission_ids'], JSON_THROW_ON_ERROR),
            'updated_at' => now(),
        ]);
    }

    /** Assign one historical audit only when the operator supplied bounded evidence. */
    private function backfillAudit(TenantAssignment $assignment): void
    {
        $updated = $this->connectionForModels()->table(AuthTables::Audits)->where('id', $assignment->recordId)->update([
            'tenant_id' => $assignment->tenantId->value,
            'ownership_key' => 'tenant:'.$assignment->tenantId->value,
            'updated_at' => now(),
        ]);
        if ($updated === 0) {
            throw new TenantBoundaryViolation('A reviewed Auth audit is unavailable.');
        }
    }

    /** Apply fixed first-release history and credential dispositions after reviewed mappings. */
    private function classifyHistoricalRows(TenantAdoptionPlan $plan): void
    {
        $connection = $this->connection($plan);
        $reviewed = [];
        foreach ($this->allAssignments($plan, 'auth.memberships') as $assignment) {
            $reviewed[$assignment->metadata['subject_type']."\0".$assignment->metadata['subject_id']] = true;
        }
        foreach ([AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions] as $table) {
            foreach ($connection->table($table)->whereNull('tenant_id')->get(['model_type', 'model_id']) as $pivot) {
                if (isset($reviewed[$pivot->model_type."\0".$pivot->model_id])) {
                    $connection->table($table)->whereNull('tenant_id')->where('model_type', $pivot->model_type)->where('model_id', $pivot->model_id)->delete();
                }
            }
        }
        $sourceIds = array_values(array_unique(array_map(
            static fn (TenantAssignment $assignment): string => $assignment->metadata['source_id'],
            $this->allAssignments($plan, 'auth.roles'),
        )));
        if ($sourceIds !== []) {
            $connection->table(AuthTables::Roles)->whereNull('tenant_id')->whereIn('id', $sourceIds)
                ->whereNotIn('id', $connection->table(AuthTables::ModelHasRoles)->whereNull('tenant_id')->select('role_id'))->delete();
        }
        $connection->table(AuthTables::PersonalAccessTokens)->whereNull('tenant_id')->delete();
        $connection->table(AuthTables::Challenges)->whereNull('tenant_id')->update([
            'ownership_key' => 'platform',
            'revoked_at' => now(),
            'updated_at' => now(),
        ]);
        $connection->table(AuthTables::Invitations)->whereNull('tenant_id')
            ->where(static function ($query): void {
                $query->whereNotNull('accepted_at')->orWhereNotNull('revoked_at')->orWhere('expires_at', '<=', now());
            })->update(['ownership_key' => 'platform', 'updated_at' => now()]);
        $connection->table(AuthTables::Audits)->whereNull('tenant_id')->update(['ownership_key' => 'platform', 'updated_at' => now()]);
    }

    /** @return list<TenantAssignment> */
    private function allAssignments(TenantAdoptionPlan $plan, string $resource): array
    {
        $assignments = [];
        $after = null;
        do {
            $batch = $this->mappings->assignments($plan, $resource, $after, 10000);
            foreach ($batch as $assignment) {
                $assignments[] = $assignment;
                $after = $assignment->recordId;
            }
        } while (count($batch) === 10000);

        return $assignments;
    }

    /** @return array{string, string|null} */
    private function cursor(?string $cursor): array
    {
        if ($cursor === null) {
            return [self::PHASES[0], null];
        }
        $parts = explode(':', $cursor, 2);
        if (count($parts) !== 2 || ! in_array($parts[0], self::PHASES, true) || $parts[1] === '') {
            throw new TenantConfigurationInvalid('The Auth adoption cursor is invalid.');
        }

        return [$parts[0], $parts[1]];
    }

    /** Assert Auth, principal, and foundation writes share one normalized connection. */
    private function assertConnections(TenantAdoptionPlan $plan): void
    {
        $this->connections->assertCompatible([$plan->connection, (new Role)->getConnectionName(), $this->principals->connectionName()]);
        $this->connection($plan);
    }

    /** Resolve and confirm Auth's canonical storage connection. */
    private function connection(TenantAdoptionPlan $plan): Connection
    {
        $connection = $this->connectionForModels();
        if ($connection->getName() !== $this->connections->name($plan->connection)) {
            throw new TenantBoundaryViolation('Auth adoption requires the canonical storage connection.');
        }

        return $connection;
    }

    /** Resolve package model storage without accepting another connection instance. */
    private function connectionForModels(): Connection
    {
        return (new Role)->getConnection();
    }

    /** Detect an invalid mixed-ownership discriminator without exposing row values. */
    private function hasInvalidOwnership(Connection $connection, string $table): bool
    {
        foreach ($connection->table($table)->get(['tenant_id', 'ownership_key']) as $row) {
            if (($row->tenant_id === null && $row->ownership_key !== 'platform')
                || (is_string($row->tenant_id) && $row->ownership_key !== 'tenant:'.$row->tenant_id)) {
                return true;
            }
        }

        return false;
    }

    /** Replace one legacy Spatie pivot key with its final tenant-leading key. */
    private function replacePivotPrimary($schema, string $table, array $columns, string $name): void
    {
        if ($schema->hasIndex($table, $name)) {
            $schema->table($table, static function (Blueprint $blueprint) use ($name): void {
                $blueprint->dropPrimary($name);
            });
        }
        $schema->table($table, static function (Blueprint $blueprint) use ($columns, $name): void {
            $blueprint->primary($columns, $name);
        });
    }
}
