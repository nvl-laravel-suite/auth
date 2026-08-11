<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\PrincipalAdoptionManifest;
use Nvl\Auth\ValueObjects\LegacyPasswordResetMapping;
use Nvl\Auth\ValueObjects\LegacyPrincipalForeignKey;
use Nvl\Auth\ValueObjects\PrincipalAdoptionPlan;
use RuntimeException;
use stdClass;

/** Plans, stages, and imports one bounded legacy principal data set. */
final readonly class AdoptPrincipalsAction
{
    public function __construct(
        private FeatureGate $features,
        private PrincipalAdoptionManifest $manifests,
        private PrincipalAttributeMapper $attributes,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
    ) {}

    /**
     * @param  array<array-key, mixed>  $manifest
     * @return array<string, mixed>
     */
    public function execute(array $manifest, bool $stage = false, bool $apply = false): array
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $plan = $this->manifests->normalize($manifest);
        $this->assertConnection($plan);

        return $stage
            ? $this->stage($plan, $apply)
            : $this->adopt($plan, $apply);
    }

    /** @return array<string, mixed> */
    private function stage(PrincipalAdoptionPlan $plan, bool $apply): array
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

        $detached = $this->existingForeignKeys($schema, $plan);

        if ($apply) {
            $this->detachForeignKeys($schema, $plan);

            foreach ($plan->stages as $stage) {
                $schema->rename($stage->sourceTable, $stage->stagingTable);
            }
        }

        return [
            'phase' => 'stage',
            'mode' => $apply ? 'apply' : 'plan',
            'renames' => array_map(static fn ($stage): array => [
                'source' => $stage->sourceTable,
                'staging' => $stage->stagingTable,
            ], $plan->stages),
            'foreign_keys_detected' => $detached,
            'foreign_keys_detached' => $apply ? $detached : [],
            'next' => 'Run enabled Auth migrations or nvl:auth:schema --apply, then rerun without --stage.',
        ];
    }

    /** @return array<string, mixed> */
    private function adopt(PrincipalAdoptionPlan $plan, bool $apply): array
    {
        [$target, $passwordTarget] = $this->assertTargetSchema($plan);
        $principals = $this->preparePrincipals($plan);
        $passwordResets = $plan->passwordResetTokens instanceof LegacyPasswordResetMapping
            ? $this->preparePasswordResets($plan, $plan->passwordResetTokens)
            : [];
        $expectedPasswordResets = $plan->passwordResetTokens instanceof LegacyPasswordResetMapping
            ? $plan->passwordResetTokens->expectedCount
            : 0;
        $this->assertSourcesDifferFromTargets($plan, $target, $passwordTarget);
        $this->assertTargetConflictsAbsent($plan, $target, $passwordTarget, $principals, $passwordResets);
        $this->assertForeignKeyReferences($plan, $principals);

        if ($apply) {
            $schema = Schema::connection($plan->connection);
            $this->detachForeignKeys($schema, $plan);
            $connection = DB::connection($plan->connection);
            $connection->transaction(function () use (
                $connection,
                $passwordResets,
                $passwordTarget,
                $principals,
                $target,
            ): void {
                $this->insertChunks($connection, $target, $principals);
                $this->insertChunks($connection, $passwordTarget, $passwordResets);
                $this->reconcile($connection, $target, $passwordTarget, $principals, $passwordResets);
            });
            $this->restoreForeignKeys($schema, $plan, $target);

            if ($plan->dropSources) {
                foreach ($this->sourceTables($plan) as $source) {
                    $schema->drop($source);
                }
            }
        }

        return [
            'phase' => 'adoption',
            'mode' => $apply ? 'apply' : 'plan',
            'reconciliation' => [
                'principals' => [
                    'expected' => $plan->principals->expectedCount,
                    'source' => count($principals),
                    'imported' => $apply ? count($principals) : 0,
                    'matched' => $apply ? count($principals) : 0,
                ],
                'password_reset_tokens' => [
                    'expected' => $expectedPasswordResets,
                    'source' => count($passwordResets),
                    'imported' => $apply ? count($passwordResets) : 0,
                    'matched' => $apply ? count($passwordResets) : 0,
                ],
            ],
            'extension_columns' => array_keys($plan->principals->extensionColumns),
            'foreign_keys_restored' => $apply ? count($plan->foreignKeys) : 0,
            'sources_dropped' => $apply && $plan->dropSources ? $this->sourceTables($plan) : [],
            'rollback' => 'Forward-only after source removal; restore a reviewed database backup for rollback.',
        ];
    }

    private function assertConnection(PrincipalAdoptionPlan $plan): void
    {
        $class = $this->models->userClass();
        $configured = (new $class)->getConnectionName() ?? config('database.default');
        $source = $plan->connection ?? config('database.default');

        if ($configured !== $source) {
            throw new InvalidArgumentException(
                'Auth principal adoption requires source and package principal storage on the same connection.',
            );
        }
    }

    /** @return array{string, string} */
    private function assertTargetSchema(PrincipalAdoptionPlan $plan): array
    {
        $class = $this->models->userClass();
        $target = (new $class)->getTable();
        $passwordTarget = $this->configuration->string(
            'tables.password_reset_tokens',
            'nvl_auth_password_reset_tokens',
        );
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

        if ($plan->passwordResetTokens instanceof LegacyPasswordResetMapping
            && (! $schema->hasTable($passwordTarget)
                || ! $schema->hasColumns($passwordTarget, ['email', 'token', 'created_at']))) {
            throw new InvalidArgumentException(
                "Canonical Auth password-reset table [{$passwordTarget}] is missing or incompatible.",
            );
        }

        return [$target, $passwordTarget];
    }

    /** @return list<array<string, mixed>> */
    private function preparePrincipals(PrincipalAdoptionPlan $plan): array
    {
        $mapping = $plan->principals;
        $sourceColumns = array_values(array_filter($mapping->columns, 'is_string'));
        $sourceColumns = array_merge($sourceColumns, array_values($mapping->extensionColumns));
        $rows = $this->sourceRows($plan, $mapping->table, $sourceColumns, $mapping->columns['id']);

        if ($rows->count() !== $mapping->expectedCount) {
            throw new InvalidArgumentException(sprintf(
                'Auth principal adoption expected %d principals but found %d.',
                $mapping->expectedCount,
                $rows->count(),
            ));
        }

        $principals = [];
        $seenIds = [];
        $seenEmails = [];

        foreach ($rows as $row) {
            $id = $this->requiredString($this->value($row, $mapping->columns, PrincipalAttribute::Id), 'principal id');
            $email = mb_strtolower($this->requiredString(
                $this->value($row, $mapping->columns, PrincipalAttribute::Email),
                "principal {$id} email",
            ));

            if (! Str::isUuid($id) || isset($seenIds[$id])) {
                throw new InvalidArgumentException("Auth principal identity [{$id}] is invalid or duplicated.");
            }

            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false
                || mb_strlen($email) > 254
                || isset($seenEmails[$email])) {
                throw new InvalidArgumentException("Auth principal email [{$email}] is invalid or duplicated.");
            }

            $seenIds[$id] = true;
            $seenEmails[$email] = true;
            $canonical = [
                PrincipalAttribute::Id->value => $id,
                PrincipalAttribute::Name->value => $this->boundedRequiredString(
                    $this->value($row, $mapping->columns, PrincipalAttribute::Name),
                    160,
                    "principal {$id} name",
                ),
                PrincipalAttribute::Email->value => $email,
                PrincipalAttribute::EmailVerifiedAt->value => $this->value($row, $mapping->columns, PrincipalAttribute::EmailVerifiedAt),
                PrincipalAttribute::Password->value => $this->nullableString($this->value($row, $mapping->columns, PrincipalAttribute::Password)),
                PrincipalAttribute::Active->value => $this->boolean($this->value($row, $mapping->columns, PrincipalAttribute::Active), true, "principal {$id} active"),
                PrincipalAttribute::Locale->value => $this->boundedString(
                    $this->value($row, $mapping->columns, PrincipalAttribute::Locale),
                    12,
                ) ?? $this->configuration->string('features.principal_management.settings.default_locale', 'en'),
                PrincipalAttribute::Timezone->value => $this->boundedString(
                    $this->value($row, $mapping->columns, PrincipalAttribute::Timezone),
                    64,
                ) ?? $this->configuration->string('features.principal_management.settings.default_timezone', 'UTC'),
                PrincipalAttribute::Profile->value => $this->encodedJson($this->value($row, $mapping->columns, PrincipalAttribute::Profile), 'profile'),
                PrincipalAttribute::Preferences->value => $this->encodedJson($this->value($row, $mapping->columns, PrincipalAttribute::Preferences), 'preferences'),
                PrincipalAttribute::LastLoginAt->value => $this->value($row, $mapping->columns, PrincipalAttribute::LastLoginAt),
                PrincipalAttribute::LastLoginIp->value => $this->encryptedString($this->value($row, $mapping->columns, PrincipalAttribute::LastLoginIp)),
                PrincipalAttribute::LockedUntil->value => $this->value($row, $mapping->columns, PrincipalAttribute::LockedUntil),
                PrincipalAttribute::RememberToken->value => $this->nullableString($this->value($row, $mapping->columns, PrincipalAttribute::RememberToken)),
                PrincipalAttribute::CreatedAt->value => $this->value($row, $mapping->columns, PrincipalAttribute::CreatedAt) ?? now(),
                PrincipalAttribute::UpdatedAt->value => $this->value($row, $mapping->columns, PrincipalAttribute::UpdatedAt) ?? now(),
                PrincipalAttribute::DeletedAt->value => $this->value($row, $mapping->columns, PrincipalAttribute::DeletedAt),
            ];
            $target = $this->attributes->map($canonical);

            foreach ($mapping->extensionColumns as $targetColumn => $sourceColumn) {
                $target[$targetColumn] = $row->{$sourceColumn} ?? null;
            }

            $principals[] = $target;
        }

        return $principals;
    }

    /** @return list<array<string, mixed>> */
    private function preparePasswordResets(
        PrincipalAdoptionPlan $plan,
        LegacyPasswordResetMapping $mapping,
    ): array {
        $sourceColumns = array_values(array_filter($mapping->columns, 'is_string'));
        $rows = $this->sourceRows($plan, $mapping->table, $sourceColumns, $mapping->columns['email']);

        if ($rows->count() !== $mapping->expectedCount) {
            throw new InvalidArgumentException(sprintf(
                'Auth principal adoption expected %d password-reset tokens but found %d.',
                $mapping->expectedCount,
                $rows->count(),
            ));
        }

        $tokens = [];
        $seen = [];

        foreach ($rows as $row) {
            $email = mb_strtolower($this->requiredString($row->{$mapping->columns['email']} ?? null, 'password-reset email'));

            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || isset($seen[$email])) {
                throw new InvalidArgumentException("Auth password-reset email [{$email}] is invalid or duplicated.");
            }

            $seen[$email] = true;
            $createdAt = $mapping->columns['created_at'];
            $tokens[] = [
                'email' => $email,
                'token' => $this->requiredString($row->{$mapping->columns['token']} ?? null, "password-reset token for {$email}"),
                'created_at' => $createdAt === null ? null : ($row->{$createdAt} ?? null),
            ];
        }

        return $tokens;
    }

    /**
     * @param  list<string>  $columns
     * @return Collection<int, stdClass>
     */
    private function sourceRows(
        PrincipalAdoptionPlan $plan,
        string $table,
        array $columns,
        ?string $orderBy,
    ): Collection {
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
    private function assertTargetConflictsAbsent(
        PrincipalAdoptionPlan $plan,
        string $target,
        string $passwordTarget,
        array $principals,
        array $passwordResets,
    ): void {
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
    private function assertForeignKeyReferences(PrincipalAdoptionPlan $plan, array $principals): void
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
            $this->assertForeignKeyTable($schema, $foreignKey);
            $references = $connection->table($foreignKey->table)
                ->whereNotNull($foreignKey->column)
                ->distinct()
                ->pluck($foreignKey->column);

            foreach ($references as $reference) {
                if (! is_scalar($reference) || ! isset($ids[(string) $reference])) {
                    throw new InvalidArgumentException(
                        "Auth principal foreign key [{$foreignKey->name}] contains an unmapped identity.",
                    );
                }
            }
        }
    }

    /**
     * @param  list<array<string, mixed>>  $principals
     * @param  list<array<string, mixed>>  $passwordResets
     */
    private function reconcile(
        Connection $connection,
        string $target,
        string $passwordTarget,
        array $principals,
        array $passwordResets,
    ): void {
        $principalIds = array_column($principals, $this->attributes->column(PrincipalAttribute::Id));
        $matched = 0;

        foreach (array_chunk($principalIds, 500) as $ids) {
            $matched += $connection->table($target)
                ->whereIn($this->attributes->column(PrincipalAttribute::Id), $ids)
                ->count();
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

    private function detachForeignKeys(Builder $schema, PrincipalAdoptionPlan $plan): void
    {
        foreach ($plan->foreignKeys as $foreignKey) {
            $this->assertForeignKeyTable($schema, $foreignKey);

            if ($this->hasForeignKey($schema->getForeignKeys($foreignKey->table), $foreignKey)) {
                $constraint = $schema->getConnection()->getDriverName() === 'sqlite'
                    ? [$foreignKey->column]
                    : $foreignKey->name;

                $schema->table(
                    $foreignKey->table,
                    static fn (Blueprint $table) => $table->dropForeign($constraint),
                );
            }
        }
    }

    private function restoreForeignKeys(Builder $schema, PrincipalAdoptionPlan $plan, string $target): void
    {
        $targetId = $this->attributes->column(PrincipalAttribute::Id);

        foreach ($plan->foreignKeys as $foreignKey) {
            if ($this->hasForeignKey($schema->getForeignKeys($foreignKey->table), $foreignKey)) {
                continue;
            }

            $missing = DB::connection($plan->connection)
                ->table($foreignKey->table)
                ->whereNotNull($foreignKey->column)
                ->whereNotExists(static function (QueryBuilder $query) use ($foreignKey, $target, $targetId): void {
                    $query->selectRaw('1')
                        ->from($target)
                        ->whereColumn("{$target}.{$targetId}", "{$foreignKey->table}.{$foreignKey->column}");
                })
                ->exists();

            if ($missing) {
                throw new RuntimeException("Auth principal foreign key [{$foreignKey->name}] is unreconciled.");
            }

            $schema->table($foreignKey->table, static function (Blueprint $table) use ($foreignKey, $target, $targetId): void {
                $definition = $table->foreign($foreignKey->column, $foreignKey->name)
                    ->references($targetId)
                    ->on($target);

                match ($foreignKey->onDelete) {
                    'cascade' => $definition->cascadeOnDelete(),
                    'null' => $definition->nullOnDelete(),
                    default => $definition->restrictOnDelete(),
                };
            });
        }
    }

    /** @return list<string> */
    private function existingForeignKeys(Builder $schema, PrincipalAdoptionPlan $plan): array
    {
        $existing = [];

        foreach ($plan->foreignKeys as $foreignKey) {
            $this->assertForeignKeyTable($schema, $foreignKey);

            if ($this->hasForeignKey($schema->getForeignKeys($foreignKey->table), $foreignKey)) {
                $existing[] = $foreignKey->name;
            }
        }

        return $existing;
    }

    private function assertForeignKeyTable(Builder $schema, LegacyPrincipalForeignKey $foreignKey): void
    {
        if (! $schema->hasTable($foreignKey->table)
            || ! $schema->hasColumn($foreignKey->table, $foreignKey->column)) {
            throw new InvalidArgumentException(
                "Auth principal foreign key [{$foreignKey->name}] has no valid host table and column.",
            );
        }
    }

    /** @param list<array<string, mixed>> $foreignKeys */
    private function hasForeignKey(array $foreignKeys, LegacyPrincipalForeignKey $expected): bool
    {
        return collect($foreignKeys)->contains(
            static fn (array $foreignKey): bool => ($foreignKey['name'] ?? null) === $expected->name
                || ($foreignKey['columns'] ?? null) === [$expected->column],
        );
    }

    /**
     * @param  list<array<string, mixed>>  $rows
     */
    private function insertChunks(Connection $connection, string $table, array $rows): void
    {
        foreach (array_chunk($rows, 250) as $chunk) {
            $connection->table($table)->insert($chunk);
        }
    }

    /** @param array<string, string|null> $columns */
    private function value(stdClass $row, array $columns, PrincipalAttribute $attribute): mixed
    {
        $source = $columns[$attribute->value];

        return $source === null ? null : ($row->{$source} ?? null);
    }

    private function requiredString(mixed $value, string $label): string
    {
        $value = $this->nullableString($value);

        if ($value === null) {
            throw new InvalidArgumentException("Auth principal adoption {$label} must be a non-empty string.");
        }

        return $value;
    }

    private function boundedRequiredString(mixed $value, int $maximum, string $label): string
    {
        $value = $this->requiredString($value, $label);

        if (mb_strlen($value) > $maximum) {
            throw new InvalidArgumentException("Auth principal adoption {$label} exceeds {$maximum} characters.");
        }

        return $value;
    }

    private function boundedString(mixed $value, int $maximum): ?string
    {
        $value = $this->nullableString($value);

        if ($value !== null && mb_strlen($value) > $maximum) {
            throw new InvalidArgumentException("Auth principal adoption value exceeds {$maximum} characters.");
        }

        return $value;
    }

    private function nullableString(mixed $value): ?string
    {
        if (! is_scalar($value)) {
            return null;
        }

        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }

    private function boolean(mixed $value, bool $default, string $label): bool
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

    private function encodedJson(mixed $value, string $label): ?string
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

    private function encryptedString(mixed $value): ?string
    {
        $value = $this->nullableString($value);

        return $value === null ? null : Crypt::encryptString($value);
    }

    private function assertSourcesDifferFromTargets(
        PrincipalAdoptionPlan $plan,
        string $target,
        string $passwordTarget,
    ): void {
        if ($plan->principals->table === $target
            || ($plan->passwordResetTokens instanceof LegacyPasswordResetMapping
                && $plan->passwordResetTokens->table === $passwordTarget)) {
            throw new InvalidArgumentException(
                'Auth principal sources must be staged away from canonical target names before adoption.',
            );
        }
    }

    /** @return list<string> */
    private function sourceTables(PrincipalAdoptionPlan $plan): array
    {
        return array_values(array_unique(array_filter([
            $plan->principals->table,
            $plan->passwordResetTokens?->table,
        ], 'is_string')));
    }
}
