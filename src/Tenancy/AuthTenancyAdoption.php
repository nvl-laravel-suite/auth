<?php

declare(strict_types=1);

namespace Nvl\Auth\Tenancy;

use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Database\Schema\Blueprint;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Models\Role;
use Nvl\Tenancy\Contracts\TenantAdoptionAdapter;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\ValueObjects\TenantAdoptionPlan;
use Nvl\Tenancy\ValueObjects\TenantBackfillResult;
use Nvl\Tenancy\ValueObjects\TenantVerification;

/** Owns Auth's independently selected tenant schema and adoption lifecycle. */
final readonly class AuthTenancyAdoption implements TenantAdoptionAdapter
{
    /** Use Laravel's migration repository without implicitly selecting this schema. */
    public function __construct(private Migrator $migrator) {}

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

    /** Prepare the empty installation's nullable ownership schema. */
    public function prepare(TenantAdoptionPlan $plan): void
    {
        $this->assertEmpty($plan);
        $path = dirname(__DIR__, 2).'/database/migrations/tenancy';
        $this->migrator->usingConnection($plan->connection, fn () => $this->migrator->run([$path], ['force' => true]));
    }

    /** Empty installations contain no ownership rows to infer. */
    public function backfill(TenantAdoptionPlan $plan, ?string $cursor, int $limit): TenantBackfillResult
    {
        $this->assertEmpty($plan);

        return new TenantBackfillResult(null, 0);
    }

    /** Verify the prepared or active shape from the database catalog. */
    public function verify(TenantAdoptionPlan $plan): TenantVerification
    {
        $schema = $this->connection($plan)->getSchemaBuilder();
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

        return new TenantVerification($errors);
    }

    /** Install final empty-schema role and assignment constraints idempotently. */
    public function activate(TenantAdoptionPlan $plan): void
    {
        $connection = $this->connection($plan);
        $schema = $connection->getSchemaBuilder();
        $this->assertEmpty($plan);

        if ($schema->hasIndex(AuthTables::Roles, 'nvl_auth_roles_name_guard_unique')) {
            $schema->table(AuthTables::Roles, static function (Blueprint $table): void {
                $table->dropUnique('nvl_auth_roles_name_guard_unique');
            });
        }
        if (! $schema->hasIndex(AuthTables::Roles, 'nvl_auth_roles_tenant_name_guard_unique')) {
            $schema->table(AuthTables::Roles, static function (Blueprint $table): void {
                $table->unique(['tenant_id', 'name', 'guard_name'], 'nvl_auth_roles_tenant_name_guard_unique');
                $table->unique(['tenant_id', 'id'], 'nvl_auth_roles_tenant_id_unique');
            });
        }

        foreach ([AuthTables::Roles, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions] as $table) {
            $schema->table($table, static function (Blueprint $blueprint): void {
                $blueprint->uuid('tenant_id')->nullable(false)->change();
            });
        }

        if ($schema->hasIndex(AuthTables::ModelHasRoles, 'nvl_auth_model_roles_primary')) {
            $schema->table(AuthTables::ModelHasRoles, static function (Blueprint $table): void {
                $table->dropPrimary('nvl_auth_model_roles_primary');
                $table->primary(['tenant_id', 'role_id', 'model_id', 'model_type'], 'nvl_auth_model_roles_primary');
            });
        }
        if ($schema->hasIndex(AuthTables::ModelHasPermissions, 'nvl_auth_model_permissions_primary')) {
            $schema->table(AuthTables::ModelHasPermissions, static function (Blueprint $table): void {
                $table->dropPrimary('nvl_auth_model_permissions_primary');
                $table->primary(['tenant_id', 'permission_id', 'model_id', 'model_type'], 'nvl_auth_model_permissions_primary');
            });
        }

        if (! $this->verify($plan)->passed()) {
            throw new TenantBoundaryViolation('Auth tenant schema did not verify after activation.');
        }
    }

    /** Resolve and confirm Auth's canonical storage connection. */
    private function connection(TenantAdoptionPlan $plan): Connection
    {
        $connection = (new Role)->getConnection();
        if ($connection->getName() !== $plan->connection) {
            throw new TenantBoundaryViolation('Auth adoption requires the canonical storage connection.');
        }

        return $connection;
    }

    /** Reject historical ownership until Task 10's reviewed mapping workflow. */
    private function assertEmpty(TenantAdoptionPlan $plan): void
    {
        $connection = $this->connection($plan);
        foreach ([
            AuthTables::Roles,
            AuthTables::ModelHasRoles,
            AuthTables::ModelHasPermissions,
            AuthTables::Invitations,
            AuthTables::PersonalAccessTokens,
            AuthTables::Challenges,
            AuthTables::Audits,
        ] as $table) {
            if ($connection->getSchemaBuilder()->hasTable($table) && $connection->table($table)->exists()) {
                throw new TenantBoundaryViolation('Existing Auth rows require the explicit historical adoption workflow.');
            }
        }
    }
}
