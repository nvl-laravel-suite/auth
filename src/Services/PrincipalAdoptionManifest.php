<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use InvalidArgumentException;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\ValueObjects\LegacyPasswordResetMapping;
use Nvl\Auth\ValueObjects\LegacyPrincipalForeignKey;
use Nvl\Auth\ValueObjects\LegacyPrincipalMapping;
use Nvl\Auth\ValueObjects\LegacyPrincipalTableStage;
use Nvl\Auth\ValueObjects\PrincipalAdoptionPlan;

/** Validates the complete legacy-to-package principal adoption manifest. */
final class PrincipalAdoptionManifest
{
    /**
     * @param  array<array-key, mixed>  $manifest
     */
    public function normalize(array $manifest): PrincipalAdoptionPlan
    {
        $this->rejectUnknown($manifest, [
            'version',
            'connection',
            'staging',
            'principals',
            'password_reset_tokens',
            'foreign_keys',
            'drop_sources',
        ], 'manifest');

        if (($manifest['version'] ?? null) !== 1) {
            throw new InvalidArgumentException('Auth principal adoption manifest version must be 1.');
        }

        $connection = $manifest['connection'] ?? config('nvl-auth.connection');

        if ($connection !== null && (! is_string($connection) || trim($connection) === '')) {
            throw new InvalidArgumentException('Auth principal adoption connection must be a name or null.');
        }

        $principals = $this->principals($manifest['principals'] ?? null);
        $passwordResets = $this->passwordResets($manifest['password_reset_tokens'] ?? null);
        $maximum = config('nvl-auth.adoption.maximum_records', 10_000);

        if (! is_int($maximum) || $maximum < 1) {
            throw new InvalidArgumentException('nvl-auth.adoption.maximum_records must be a positive integer.');
        }

        $passwordResetCount = $passwordResets instanceof LegacyPasswordResetMapping
            ? $passwordResets->expectedCount
            : 0;

        if ($principals->expectedCount + $passwordResetCount > $maximum) {
            throw new InvalidArgumentException(
                "Auth principal adoption exceeds the configured {$maximum} record limit.",
            );
        }

        return new PrincipalAdoptionPlan(
            connection: is_string($connection) ? trim($connection) : null,
            stages: $this->stages($manifest['staging'] ?? []),
            principals: $principals,
            passwordResetTokens: $passwordResets,
            foreignKeys: $this->foreignKeys($manifest['foreign_keys'] ?? []),
            dropSources: ($manifest['drop_sources'] ?? false) === true,
        );
    }

    private function principals(mixed $value): LegacyPrincipalMapping
    {
        if (! is_array($value) || array_is_list($value)) {
            throw new InvalidArgumentException('Auth principal adoption principals must be an object.');
        }

        $this->rejectUnknown($value, ['table', 'expected_count', 'columns', 'extension_columns'], 'principals');
        $columns = $value['columns'] ?? null;

        if (! is_array($columns) || array_is_list($columns)) {
            throw new InvalidArgumentException('Auth principal adoption columns must be an object.');
        }

        $normalized = [];

        foreach (PrincipalAttribute::cases() as $attribute) {
            if (! array_key_exists($attribute->value, $columns)) {
                throw new InvalidArgumentException(
                    "Auth principal adoption columns must explicitly map [{$attribute->value}].",
                );
            }

            $source = $columns[$attribute->value];

            if ($source !== null && ! is_string($source)) {
                throw new InvalidArgumentException(
                    "Auth principal adoption column [{$attribute->value}] must be a source column or null.",
                );
            }

            $normalized[$attribute->value] = $source === null
                ? null
                : $this->identifier($source, "principal {$attribute->value} column");
        }

        foreach ([PrincipalAttribute::Id, PrincipalAttribute::Name, PrincipalAttribute::Email] as $required) {
            if (($normalized[$required->value] ?? null) === null) {
                throw new InvalidArgumentException(
                    "Auth principal adoption column [{$required->value}] cannot be null.",
                );
            }
        }

        return new LegacyPrincipalMapping(
            table: $this->identifier($value['table'] ?? null, 'principal table'),
            expectedCount: $this->count($value['expected_count'] ?? null, 'principals'),
            columns: $normalized,
            extensionColumns: $this->stringMap($value['extension_columns'] ?? [], 'extension_columns'),
        );
    }

    private function passwordResets(mixed $value): ?LegacyPasswordResetMapping
    {
        if ($value === null) {
            return null;
        }

        if (! is_array($value) || array_is_list($value)) {
            throw new InvalidArgumentException('Auth principal adoption password_reset_tokens must be an object.');
        }

        $this->rejectUnknown($value, ['table', 'expected_count', 'columns'], 'password_reset_tokens');
        $columns = $value['columns'] ?? null;

        if (! is_array($columns) || array_is_list($columns)) {
            throw new InvalidArgumentException('Auth password-reset columns must be an object.');
        }

        $this->rejectUnknown($columns, ['email', 'token', 'created_at'], 'password-reset columns');

        foreach (['email', 'token'] as $required) {
            if (! isset($columns[$required]) || ! is_string($columns[$required])) {
                throw new InvalidArgumentException("Auth password-reset column [{$required}] is required.");
            }
        }

        $createdAt = $columns['created_at'] ?? null;

        if ($createdAt !== null && ! is_string($createdAt)) {
            throw new InvalidArgumentException('Auth password-reset created_at must be a source column or null.');
        }

        return new LegacyPasswordResetMapping(
            table: $this->identifier($value['table'] ?? null, 'password-reset table'),
            expectedCount: $this->count($value['expected_count'] ?? null, 'password-reset tokens'),
            columns: [
                'email' => $this->identifier($columns['email'], 'password-reset email column'),
                'token' => $this->identifier($columns['token'], 'password-reset token column'),
                'created_at' => $createdAt === null
                    ? null
                    : $this->identifier($createdAt, 'password-reset created_at column'),
            ],
        );
    }

    /** @return list<LegacyPrincipalTableStage> */
    private function stages(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidArgumentException('Auth principal adoption staging must be a JSON list.');
        }

        $stages = [];
        $tables = [];

        foreach ($value as $entry) {
            if (! is_array($entry)) {
                throw new InvalidArgumentException('Every Auth principal staging entry must be an object.');
            }

            $this->rejectUnknown($entry, ['source_table', 'staging_table'], 'staging entry');
            $source = $this->identifier($entry['source_table'] ?? null, 'staging source_table');
            $target = $this->identifier($entry['staging_table'] ?? null, 'staging staging_table');

            if ($source === $target || isset($tables[$source]) || isset($tables[$target])) {
                throw new InvalidArgumentException('Auth principal staging table names must be distinct.');
            }

            $tables[$source] = true;
            $tables[$target] = true;
            $stages[] = new LegacyPrincipalTableStage($source, $target);
        }

        return $stages;
    }

    /** @return list<LegacyPrincipalForeignKey> */
    private function foreignKeys(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidArgumentException('Auth principal adoption foreign_keys must be a JSON list.');
        }

        $foreignKeys = [];

        foreach ($value as $entry) {
            if (! is_array($entry)) {
                throw new InvalidArgumentException('Every Auth principal foreign key must be an object.');
            }

            $this->rejectUnknown($entry, ['table', 'column', 'name', 'on_delete'], 'foreign key');
            $onDelete = $entry['on_delete'] ?? 'restrict';

            if (! in_array($onDelete, ['cascade', 'null', 'restrict'], true)) {
                throw new InvalidArgumentException('Auth principal foreign key on_delete is invalid.');
            }

            $foreignKeys[] = new LegacyPrincipalForeignKey(
                table: $this->identifier($entry['table'] ?? null, 'foreign key table'),
                column: $this->identifier($entry['column'] ?? null, 'foreign key column'),
                name: $this->identifier($entry['name'] ?? null, 'foreign key name'),
                onDelete: $onDelete,
            );
        }

        return $foreignKeys;
    }

    /**
     * @return array<string, string>
     */
    private function stringMap(mixed $value, string $label): array
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException("Auth principal adoption {$label} must be an object.");
        }

        $map = [];

        foreach ($value as $target => $source) {
            if (! is_string($target) || ! is_string($source)) {
                throw new InvalidArgumentException("Auth principal adoption {$label} contains an invalid entry.");
            }

            $map[$this->identifier($target, "{$label} target")] = $this->identifier($source, "{$label} source");
        }

        return $map;
    }

    private function identifier(mixed $value, string $label): string
    {
        if (! is_string($value)
            || preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,62}$/', $value) !== 1) {
            throw new InvalidArgumentException(
                "Auth principal adoption {$label} must be a valid database identifier of at most 63 characters.",
            );
        }

        return $value;
    }

    private function count(mixed $value, string $label): int
    {
        if (! is_int($value) || $value < 0) {
            throw new InvalidArgumentException("Auth principal adoption {$label} expected_count must be non-negative.");
        }

        return $value;
    }

    /**
     * @param  array<array-key, mixed>  $value
     * @param  list<string>  $allowed
     */
    private function rejectUnknown(array $value, array $allowed, string $label): void
    {
        $unknown = array_values(array_diff(array_keys($value), $allowed));

        if ($unknown !== []) {
            $key = is_string($unknown[0]) ? $unknown[0] : (string) $unknown[0];

            throw new InvalidArgumentException(
                "Auth principal adoption {$label} contains unknown key [{$key}].",
            );
        }
    }
}
