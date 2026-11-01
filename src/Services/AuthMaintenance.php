<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder as SchemaBuilder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Impersonation;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\PendingEmailChange;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\ValueObjects\LegacyPasswordResetMapping;
use Nvl\Auth\ValueObjects\LegacyPrincipalForeignKey;
use Nvl\Auth\ValueObjects\PrincipalAdoptionPlan;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use RuntimeException;
use stdClass;

/**
 * Complete native AuthMaintenance operations.
 *
 * @api
 */
final readonly class AuthMaintenance
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private PrincipalAdoptionManifest $manifests, private PrincipalAttributeMapper $attributes, private AuthModelRegistry $models, private AuthConfiguration $configuration, private AuthAuditRecorder $audits, private MutationAuthorizer $mutations) {}

    /**
     * @param  array<array-key, mixed>  $manifest
     * @return array<string, mixed>
     */
    public function adoptPrincipals(array $manifest, Authenticatable|SystemMutationContext $authority, bool $stage = false, bool $apply = false): array
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $this->mutations->authorize($authority, 'nvl.auth.users.adopt');
        $plan = $this->manifests->normalize($manifest);
        $this->adoptPrincipalsAssertConnection($plan);

        return $stage ? $this->adoptPrincipalsStage($plan, $apply) : $this->adoptPrincipalsAdopt($plan, $apply);
    }

    /** @return array<string, mixed> */
    private function adoptPrincipalsStage(PrincipalAdoptionPlan $plan, bool $apply): array
    {
        if ($plan->stages === []) {
            throw new InvalidArgumentException('Auth principal staging requires at least one table rename.');
        }
        $schema = Schema::connection($plan->connection);
        foreach ($plan->stages as $stage) {
            if (! $schema->hasTable($stage->sourceTable)) {
                throw new InvalidArgumentException("Auth principal staging source [{$stage->sourceTable}] does not exist.");
            }
            if ($schema->hasTable($stage->stagingTable)) {
                throw new InvalidArgumentException("Auth principal staging target [{$stage->stagingTable}] already exists.");
            }
        }
        $detached = $this->adoptPrincipalsExistingForeignKeys($schema, $plan);
        if ($apply) {
            $this->adoptPrincipalsDetachForeignKeys($schema, $plan);
            foreach ($plan->stages as $stage) {
                $schema->rename($stage->sourceTable, $stage->stagingTable);
            }
        }

        return ['phase' => 'stage', 'mode' => $apply ? 'apply' : 'plan', 'renames' => array_map(static fn ($stage): array => ['source' => $stage->sourceTable, 'staging' => $stage->stagingTable], $plan->stages), 'foreign_keys_detected' => $detached, 'foreign_keys_detached' => $apply ? $detached : [], 'next' => 'Run enabled Auth migrations or nvl:auth:schema --apply, then rerun without --stage.'];
    }

    /** @return array<string, mixed> */
    private function adoptPrincipalsAdopt(PrincipalAdoptionPlan $plan, bool $apply): array
    {
        [$target, $passwordTarget] = $this->adoptPrincipalsAssertTargetSchema($plan);
        $principals = $this->adoptPrincipalsPreparePrincipals($plan);
        $passwordResets = $plan->passwordResetTokens instanceof LegacyPasswordResetMapping ? $this->adoptPrincipalsPreparePasswordResets($plan, $plan->passwordResetTokens) : [];
        $expectedPasswordResets = $plan->passwordResetTokens instanceof LegacyPasswordResetMapping ? $plan->passwordResetTokens->expectedCount : 0;
        $this->adoptPrincipalsAssertSourcesDifferFromTargets($plan, $target, $passwordTarget);
        $this->adoptPrincipalsAssertTargetConflictsAbsent($plan, $target, $passwordTarget, $principals, $passwordResets);
        $this->adoptPrincipalsAssertForeignKeyReferences($plan, $principals);
        if ($apply) {
            $schema = Schema::connection($plan->connection);
            $this->adoptPrincipalsDetachForeignKeys($schema, $plan);
            $connection = DB::connection($plan->connection);
            $connection->transaction(function () use ($connection, $passwordResets, $passwordTarget, $principals, $target): void {
                $this->adoptPrincipalsInsertChunks($connection, $target, $principals);
                $this->adoptPrincipalsInsertChunks($connection, $passwordTarget, $passwordResets);
                $this->adoptPrincipalsReconcile($connection, $target, $passwordTarget, $principals, $passwordResets);
            });
            $this->adoptPrincipalsRestoreForeignKeys($schema, $plan, $target);
            if ($plan->dropSources) {
                foreach ($this->adoptPrincipalsSourceTables($plan) as $source) {
                    $schema->drop($source);
                }
            }
        }

        return ['phase' => 'adoption', 'mode' => $apply ? 'apply' : 'plan', 'reconciliation' => ['principals' => ['expected' => $plan->principals->expectedCount, 'source' => count($principals), 'imported' => $apply ? count($principals) : 0, 'matched' => $apply ? count($principals) : 0], 'password_reset_tokens' => ['expected' => $expectedPasswordResets, 'source' => count($passwordResets), 'imported' => $apply ? count($passwordResets) : 0, 'matched' => $apply ? count($passwordResets) : 0]], 'extension_columns' => array_keys($plan->principals->extensionColumns), 'foreign_keys_restored' => $apply ? count($plan->foreignKeys) : 0, 'sources_dropped' => $apply && $plan->dropSources ? $this->adoptPrincipalsSourceTables($plan) : [], 'rollback' => 'Forward-only after source removal; restore a reviewed database backup for rollback.'];
    }

    /** Native Auth operation. */
    private function adoptPrincipalsAssertConnection(PrincipalAdoptionPlan $plan): void
    {
        $class = $this->models->userClass();
        $configured = (new $class)->getConnectionName() ?? config('database.default');
        $source = $plan->connection ?? config('database.default');
        if ($configured !== $source) {
            throw new InvalidArgumentException('Auth principal adoption requires source and package principal storage on the same connection.');
        }
    }

    /** @return array{string, string} */
    private function adoptPrincipalsAssertTargetSchema(PrincipalAdoptionPlan $plan): array
    {
        $class = $this->models->userClass();
        $target = (new $class)->getTable();
        $passwordTarget = $this->configuration->string('tables.password_reset_tokens', AuthTables::get(AuthTables::PasswordResetTokens));
        $schema = Schema::connection($plan->connection);
        if (! $schema->hasTable($target)) {
            throw new InvalidArgumentException("Canonical Auth principal table [{$target}] does not exist.");
        }
        $targetColumns = array_map($this->attributes->column(...), PrincipalAttribute::cases());
        foreach (array_merge($targetColumns, array_keys($plan->principals->extensionColumns)) as $column) {
            if (! $schema->hasColumn($target, $column)) {
                throw new InvalidArgumentException("Canonical Auth principal table [{$target}] is missing [{$column}].");
            }
        }
        if (array_intersect($targetColumns, array_keys($plan->principals->extensionColumns)) !== []) {
            throw new InvalidArgumentException('Auth principal extension columns cannot replace mapped package attributes.');
        }
        if ($plan->passwordResetTokens instanceof LegacyPasswordResetMapping && (! $schema->hasTable($passwordTarget) || ! $schema->hasColumns($passwordTarget, ['email', 'token', 'created_at']))) {
            throw new InvalidArgumentException("Canonical Auth password-reset table [{$passwordTarget}] is missing or incompatible.");
        }

        return [$target, $passwordTarget];
    }

    /** @return list<array<string, mixed>> */
    private function adoptPrincipalsPreparePrincipals(PrincipalAdoptionPlan $plan): array
    {
        $mapping = $plan->principals;
        $sourceColumns = array_values(array_filter($mapping->columns, 'is_string'));
        $sourceColumns = array_merge($sourceColumns, array_values($mapping->extensionColumns));
        $rows = $this->adoptPrincipalsSourceRows($plan, $mapping->table, $sourceColumns, $mapping->columns['id']);
        if ($rows->count() !== $mapping->expectedCount) {
            throw new InvalidArgumentException(sprintf('Auth principal adoption expected %d principals but found %d.', $mapping->expectedCount, $rows->count()));
        }
        $principals = [];
        $seenIds = [];
        $seenEmails = [];
        foreach ($rows as $row) {
            $id = $this->adoptPrincipalsRequiredString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Id), 'principal id');
            $email = PrincipalEmailIdentity::normalize($this->adoptPrincipalsRequiredString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Email), "principal {$id} email"));
            if (! Str::isUuid($id) || isset($seenIds[$id])) {
                throw new InvalidArgumentException("Auth principal identity [{$id}] is invalid or duplicated.");
            }
            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || mb_strlen($email) > 254 || isset($seenEmails[$email])) {
                throw new InvalidArgumentException("Auth principal email [{$email}] is invalid or duplicated.");
            }
            $seenIds[$id] = true;
            $seenEmails[$email] = true;
            $canonical = [PrincipalAttribute::Id->value => $id, PrincipalAttribute::Name->value => $this->adoptPrincipalsBoundedRequiredString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Name), 160, "principal {$id} name"), PrincipalAttribute::Email->value => $email, PrincipalAttribute::EmailVerifiedAt->value => $this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::EmailVerifiedAt), PrincipalAttribute::Password->value => $this->adoptPrincipalsNullableString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Password)), PrincipalAttribute::Active->value => $this->adoptPrincipalsBoolean($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Active), true, "principal {$id} active"), PrincipalAttribute::Locale->value => $this->adoptPrincipalsBoundedString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Locale), 12) ?? $this->configuration->string('features.principal_management.settings.default_locale', 'en'), PrincipalAttribute::Timezone->value => $this->adoptPrincipalsBoundedString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Timezone), 64) ?? $this->configuration->string('features.principal_management.settings.default_timezone', 'UTC'), PrincipalAttribute::Profile->value => $this->adoptPrincipalsEncodedJson($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Profile), 'profile'), PrincipalAttribute::Preferences->value => $this->adoptPrincipalsEncodedJson($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::Preferences), 'preferences'), PrincipalAttribute::LastLoginAt->value => $this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::LastLoginAt), PrincipalAttribute::LastLoginIp->value => $this->adoptPrincipalsEncryptedString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::LastLoginIp)), PrincipalAttribute::LockedUntil->value => $this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::LockedUntil), PrincipalAttribute::RememberToken->value => $this->adoptPrincipalsNullableString($this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::RememberToken)), PrincipalAttribute::CreatedAt->value => $this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::CreatedAt) ?? now(), PrincipalAttribute::UpdatedAt->value => $this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::UpdatedAt) ?? now(), PrincipalAttribute::DeletedAt->value => $this->adoptPrincipalsValue($row, $mapping->columns, PrincipalAttribute::DeletedAt)];
            $target = $this->attributes->map($canonical);
            foreach ($mapping->extensionColumns as $targetColumn => $sourceColumn) {
                $target[$targetColumn] = $row->{$sourceColumn} ?? null;
            }
            $principals[] = $target;
        }

        return $principals;
    }

    /** @return list<array<string, mixed>> */
    private function adoptPrincipalsPreparePasswordResets(PrincipalAdoptionPlan $plan, LegacyPasswordResetMapping $mapping): array
    {
        $sourceColumns = array_values(array_filter($mapping->columns, 'is_string'));
        $rows = $this->adoptPrincipalsSourceRows($plan, $mapping->table, $sourceColumns, $mapping->columns['email']);
        if ($rows->count() !== $mapping->expectedCount) {
            throw new InvalidArgumentException(sprintf('Auth principal adoption expected %d password-reset tokens but found %d.', $mapping->expectedCount, $rows->count()));
        }
        $tokens = [];
        $seen = [];
        foreach ($rows as $row) {
            $email = PrincipalEmailIdentity::normalize($this->adoptPrincipalsRequiredString($row->{$mapping->columns['email']} ?? null, 'password-reset email'));
            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || isset($seen[$email])) {
                throw new InvalidArgumentException("Auth password-reset email [{$email}] is invalid or duplicated.");
            }
            $seen[$email] = true;
            $createdAt = $mapping->columns['created_at'];
            $tokens[] = ['email' => $email, 'token' => $this->adoptPrincipalsRequiredString($row->{$mapping->columns['token']} ?? null, "password-reset token for {$email}"), 'created_at' => $createdAt === null ? null : $row->{$createdAt} ?? null];
        }

        return $tokens;
    }

    /**
     * @param  list<string>  $columns
     * @return Collection<int, stdClass>
     */
    private function adoptPrincipalsSourceRows(PrincipalAdoptionPlan $plan, string $table, array $columns, ?string $orderBy): Collection
    {
        $schema = Schema::connection($plan->connection);
        if (! $schema->hasTable($table)) {
            throw new InvalidArgumentException("Auth principal source table [{$table}] does not exist.");
        }
        foreach (array_unique($columns) as $column) {
            if (! $schema->hasColumn($table, $column)) {
                throw new InvalidArgumentException("Auth principal source [{$table}] is missing [{$column}].");
            }
        }
        $query = DB::connection($plan->connection)->table($table);
        if ($orderBy !== null) {
            $query->orderBy($orderBy);
        }

        return $query->get();
    }

    /**
     * @param  list<array<string, mixed>>  $principals
     * @param  list<array<string, mixed>>  $passwordResets
     */
    private function adoptPrincipalsAssertTargetConflictsAbsent(PrincipalAdoptionPlan $plan, string $target, string $passwordTarget, array $principals, array $passwordResets): void
    {
        $connection = DB::connection($plan->connection);
        $id = $this->attributes->column(PrincipalAttribute::Id);
        $email = $this->attributes->column(PrincipalAttribute::Email);
        foreach (array_chunk(array_column($principals, $id), 500) as $ids) {
            if ($connection->table($target)->whereIn($id, $ids)->exists()) {
                throw new InvalidArgumentException('Auth principal target already contains a source identity.');
            }
        }
        foreach (array_chunk(array_column($principals, $email), 500) as $emails) {
            if ($connection->table($target)->whereIn($email, $emails)->exists()) {
                throw new InvalidArgumentException('Auth principal target already contains a source email.');
            }
        }
        foreach (array_chunk(array_column($passwordResets, 'email'), 500) as $emails) {
            if ($connection->table($passwordTarget)->whereIn('email', $emails)->exists()) {
                throw new InvalidArgumentException('Auth password-reset target already contains a source email.');
            }
        }
    }

    /** @param list<array<string, mixed>> $principals */
    private function adoptPrincipalsAssertForeignKeyReferences(PrincipalAdoptionPlan $plan, array $principals): void
    {
        $ids = [];
        foreach (array_column($principals, $this->attributes->column(PrincipalAttribute::Id)) as $identifier) {
            if (! is_string($identifier) && ! is_int($identifier)) {
                throw new InvalidArgumentException('Auth principal adoption produced an invalid target identity.');
            }
            $ids[(string) $identifier] = true;
        }
        $connection = DB::connection($plan->connection);
        $schema = Schema::connection($plan->connection);
        foreach ($plan->foreignKeys as $foreignKey) {
            $this->adoptPrincipalsAssertForeignKeyTable($schema, $foreignKey);
            $references = $connection->table($foreignKey->table)->whereNotNull($foreignKey->column)->distinct()->pluck($foreignKey->column);
            foreach ($references as $reference) {
                if (! is_scalar($reference) || ! isset($ids[(string) $reference])) {
                    throw new InvalidArgumentException("Auth principal foreign key [{$foreignKey->name}] contains an unmapped identity.");
                }
            }
        }
    }

    /**
     * @param  list<array<string, mixed>>  $principals
     * @param  list<array<string, mixed>>  $passwordResets
     */
    private function adoptPrincipalsReconcile(Connection $connection, string $target, string $passwordTarget, array $principals, array $passwordResets): void
    {
        $principalIds = array_column($principals, $this->attributes->column(PrincipalAttribute::Id));
        $matched = 0;
        foreach (array_chunk($principalIds, 500) as $ids) {
            $matched += $connection->table($target)->whereIn($this->attributes->column(PrincipalAttribute::Id), $ids)->count();
        }
        if ($matched !== count($principals)) {
            throw new RuntimeException('Auth principal adoption failed principal identity reconciliation.');
        }
        $matchedTokens = 0;
        foreach (array_chunk(array_column($passwordResets, 'email'), 500) as $emails) {
            $matchedTokens += $connection->table($passwordTarget)->whereIn('email', $emails)->count();
        }
        if ($matchedTokens !== count($passwordResets)) {
            throw new RuntimeException('Auth principal adoption failed password-reset reconciliation.');
        }
    }

    /** Native Auth operation. */
    private function adoptPrincipalsDetachForeignKeys(SchemaBuilder $schema, PrincipalAdoptionPlan $plan): void
    {
        foreach ($plan->foreignKeys as $foreignKey) {
            $this->adoptPrincipalsAssertForeignKeyTable($schema, $foreignKey);
            if ($this->adoptPrincipalsHasForeignKey($schema->getForeignKeys($foreignKey->table), $foreignKey)) {
                $constraint = $schema->getConnection()->getDriverName() === 'sqlite' ? [$foreignKey->column] : $foreignKey->name;
                $schema->table($foreignKey->table, static fn (Blueprint $table) => $table->dropForeign($constraint));
            }
        }
    }

    /** Native Auth operation. */
    private function adoptPrincipalsRestoreForeignKeys(SchemaBuilder $schema, PrincipalAdoptionPlan $plan, string $target): void
    {
        $targetId = $this->attributes->column(PrincipalAttribute::Id);
        foreach ($plan->foreignKeys as $foreignKey) {
            if ($this->adoptPrincipalsHasForeignKey($schema->getForeignKeys($foreignKey->table), $foreignKey)) {
                continue;
            }
            $missing = DB::connection($plan->connection)->table($foreignKey->table)->whereNotNull($foreignKey->column)->whereNotExists(static function (QueryBuilder $query) use ($foreignKey, $target, $targetId): void {
                $query->selectRaw('1')->from($target)->whereColumn("{$target}.{$targetId}", "{$foreignKey->table}.{$foreignKey->column}");
            })->exists();
            if ($missing) {
                throw new RuntimeException("Auth principal foreign key [{$foreignKey->name}] is unreconciled.");
            }
            $schema->table($foreignKey->table, static function (Blueprint $table) use ($foreignKey, $target, $targetId): void {
                $definition = $table->foreign($foreignKey->column, $foreignKey->name)->references($targetId)->on($target);
                match ($foreignKey->onDelete) {
                    'cascade' => $definition->cascadeOnDelete(),
                    'null' => $definition->nullOnDelete(),
                    default => $definition->restrictOnDelete(),
                };
            });
        }
    }

    /** @return list<string> */
    private function adoptPrincipalsExistingForeignKeys(SchemaBuilder $schema, PrincipalAdoptionPlan $plan): array
    {
        $existing = [];
        foreach ($plan->foreignKeys as $foreignKey) {
            $this->adoptPrincipalsAssertForeignKeyTable($schema, $foreignKey);
            if ($this->adoptPrincipalsHasForeignKey($schema->getForeignKeys($foreignKey->table), $foreignKey)) {
                $existing[] = $foreignKey->name;
            }
        }

        return $existing;
    }

    /** Native Auth operation. */
    private function adoptPrincipalsAssertForeignKeyTable(SchemaBuilder $schema, LegacyPrincipalForeignKey $foreignKey): void
    {
        if (! $schema->hasTable($foreignKey->table) || ! $schema->hasColumn($foreignKey->table, $foreignKey->column)) {
            throw new InvalidArgumentException("Auth principal foreign key [{$foreignKey->name}] has no valid host table and column.");
        }
    }

    /** @param list<array<string, mixed>> $foreignKeys */
    private function adoptPrincipalsHasForeignKey(array $foreignKeys, LegacyPrincipalForeignKey $expected): bool
    {
        return collect($foreignKeys)->contains(static fn (array $foreignKey): bool => ($foreignKey['name'] ?? null) === $expected->name || ($foreignKey['columns'] ?? null) === [$expected->column]);
    }

    /**
     * @param  list<array<string, mixed>>  $rows
     */
    private function adoptPrincipalsInsertChunks(Connection $connection, string $table, array $rows): void
    {
        foreach (array_chunk($rows, 250) as $chunk) {
            $connection->table($table)->insert($chunk);
        }
    }

    /** @param array<string, string|null> $columns */
    private function adoptPrincipalsValue(stdClass $row, array $columns, PrincipalAttribute $attribute): mixed
    {
        $source = $columns[$attribute->value];

        return $source === null ? null : $row->{$source} ?? null;
    }

    /** Native Auth operation. */
    private function adoptPrincipalsRequiredString(mixed $value, string $label): string
    {
        $value = $this->adoptPrincipalsNullableString($value);
        if ($value === null) {
            throw new InvalidArgumentException("Auth principal adoption {$label} must be a non-empty string.");
        }

        return $value;
    }

    /** Native Auth operation. */
    private function adoptPrincipalsBoundedRequiredString(mixed $value, int $maximum, string $label): string
    {
        $value = $this->adoptPrincipalsRequiredString($value, $label);
        if (mb_strlen($value) > $maximum) {
            throw new InvalidArgumentException("Auth principal adoption {$label} exceeds {$maximum} characters.");
        }

        return $value;
    }

    /** Native Auth operation. */
    private function adoptPrincipalsBoundedString(mixed $value, int $maximum): ?string
    {
        $value = $this->adoptPrincipalsNullableString($value);
        if ($value !== null && mb_strlen($value) > $maximum) {
            throw new InvalidArgumentException("Auth principal adoption value exceeds {$maximum} characters.");
        }

        return $value;
    }

    /** Native Auth operation. */
    private function adoptPrincipalsNullableString(mixed $value): ?string
    {
        if (! is_scalar($value)) {
            return null;
        }
        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }

    /** Native Auth operation. */
    private function adoptPrincipalsBoolean(mixed $value, bool $default, string $label): bool
    {
        if ($value === null) {
            return $default;
        }
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 1 || $value === '1') {
            return true;
        }
        if ($value === 0 || $value === '0') {
            return false;
        }
        throw new InvalidArgumentException("Auth principal adoption {$label} must be boolean.");
    }

    /** Native Auth operation. */
    private function adoptPrincipalsEncodedJson(mixed $value, string $label): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_string($value)) {
            $decoded = json_decode($value, true, 512, JSON_THROW_ON_ERROR);
            if (! is_array($decoded)) {
                throw new InvalidArgumentException("Auth principal adoption {$label} must be JSON.");
            }

            return json_encode($decoded, JSON_THROW_ON_ERROR);
        }
        if (! is_array($value)) {
            throw new InvalidArgumentException("Auth principal adoption {$label} must be JSON.");
        }

        return json_encode($value, JSON_THROW_ON_ERROR);
    }

    /** Native Auth operation. */
    private function adoptPrincipalsEncryptedString(mixed $value): ?string
    {
        $value = $this->adoptPrincipalsNullableString($value);

        return $value === null ? null : Crypt::encryptString($value);
    }

    /** Native Auth operation. */
    private function adoptPrincipalsAssertSourcesDifferFromTargets(PrincipalAdoptionPlan $plan, string $target, string $passwordTarget): void
    {
        if ($plan->principals->table === $target || $plan->passwordResetTokens instanceof LegacyPasswordResetMapping && $plan->passwordResetTokens->table === $passwordTarget) {
            throw new InvalidArgumentException('Auth principal sources must be staged away from canonical target names before adoption.');
        }
    }

    /** @return list<string> */
    private function adoptPrincipalsSourceTables(PrincipalAdoptionPlan $plan): array
    {
        return array_values(array_unique(array_filter([$plan->principals->table, $plan->passwordResetTokens?->table], 'is_string')));
    }

    /**
     * Count terminal records or delete them in bounded, freshly authorized batches.
     * Completed batches remain committed if a later batch fails. A host outer
     * transaction retains its normal commit boundary; scheduled pruning should
     * start outside a transaction. Short metadata transactions and preview counts
     * use each model's authoritative write source as deletion does.
     *
     * @return array<string, int>
     */
    public function prune(Authenticatable|SystemMutationContext $authority, bool $dryRun = false): array
    {
        $this->mutations->authorize($authority, 'nvl.auth.maintenance.prune');
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Cleanup);
        $batchSize = $this->configuration->integerBetween('cleanup.batch_size', 250, 1, 1000);
        $cutoff = AuthInstantCast::forQuery((new Invitation)->getConnection(), CarbonImmutable::now('UTC')->subDays($this->configuration->integerBetween('cleanup.retention_days', 30, 1, 3650)));
        $ownedQueries = ['invitations' => Invitation::query()->where(function (Builder $query) use ($cutoff): void {
            $query->where('expires_at', '<', $cutoff)->orWhere('accepted_at', '<', $cutoff)->orWhere('revoked_at', '<', $cutoff);
        }), 'challenges' => Challenge::query()->where(function (Builder $query) use ($cutoff): void {
            $query->where('expires_at', '<', $cutoff)->orWhere('consumed_at', '<', $cutoff)->orWhere('revoked_at', '<', $cutoff);
        })];
        $queries = $ownedQueries;
        $queries += ['impersonations' => Impersonation::query()->where('expires_at', '<', $cutoff), 'remember_credentials' => RememberCredential::query()->where('absolute_expires_at', '<', $cutoff), 'browser_sessions' => BrowserSession::query()->where('absolute_expires_at', '<', $cutoff), 'pending_email_changes' => PendingEmailChange::query()->where('expires_at', '<', $cutoff), 'totp_credentials' => TotpCredential::query()->where('revoked_at', '<', $cutoff), 'passkeys' => Passkey::query()->where('revoked_at', '<', $cutoff), 'recovery_codes' => RecoveryCode::query()->where(function (Builder $query) use ($cutoff): void {
            $query->where('used_at', '<', $cutoff)->orWhere('revoked_at', '<', $cutoff);
        }), 'social_identities' => SocialIdentity::query()->where('revoked_at', '<', $cutoff), 'client_sessions' => AuthClientSession::query()->where('ended_at', '<', $cutoff)];
        $counts = [];
        foreach ($queries as $name => $query) {
            $this->mutations->authorize($authority, 'nvl.auth.maintenance.prune');
            $model = $query->getModel();
            $exists = $model->getConnection()->transaction(fn (): bool => $model->getConnection()->getSchemaBuilder()->hasTable($model->getTable()));
            if (! $exists) {
                $counts[$name] = 0;

                continue;
            }
            $counts[$name] = $dryRun ? $query->useWritePdo()->count() : $this->pruneQuery($query, $authority, $batchSize);
        }
        if (! $dryRun) {
            $this->audits->record('auth_state.pruned', metadata: ['counts' => $counts]);
        }

        return $counts;
    }

    /**
     * Reapply retention and ownership predicates when deleting each bounded keyset.
     *
     * @param  Builder<covariant Model>  $query
     */
    private function pruneQuery(Builder $query, Authenticatable|SystemMutationContext $authority, int $batchSize): int
    {
        $key = $query->getModel()->getQualifiedKeyName();
        $after = null;
        $deleted = 0;
        do {
            $this->mutations->authorize($authority, 'nvl.auth.maintenance.prune');
            $batch = clone $query;
            if ($after !== null) {
                $batch->where($key, '>', $after);
            }
            $identifiers = $batch->useWritePdo()->orderBy($key)->limit($batchSize)->pluck($key)->all();
            if ($identifiers === []) {
                break;
            }
            $after = $identifiers[array_key_last($identifiers)];
            if (! is_string($after) && ! is_int($after)) {
                throw new \LogicException('Auth pruning requires scalar primary keys.');
            }
            $deleted += $query->getModel()->getConnection()->transaction(function () use ($query, $identifiers, $authority): int {
                $this->mutations->authorize($authority, 'nvl.auth.maintenance.prune');
                $result = (clone $query)->whereKey($identifiers)->delete();
                if (! is_int($result)) {
                    throw new \LogicException('Auth pruning returned a non-integer result.');
                }

                return $result;
            }, 3);
        } while (count($identifiers) === $batchSize);

        return $deleted;
    }
}
