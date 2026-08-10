<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

/** Resolves the validated canonical-to-physical principal field map. */
final class ConfiguredPrincipalAttributeMapper implements PrincipalAttributeMapper
{
    /** @var array<string, string>|null */
    private ?array $columns = null;

    public function column(PrincipalAttribute $attribute): string
    {
        return $this->columns()[$attribute->value];
    }

    public function identifierColumn(string $configuredIdentifier): string
    {
        $attribute = PrincipalAttribute::tryFrom($configuredIdentifier);

        if ($attribute instanceof PrincipalAttribute) {
            return $this->column($attribute);
        }

        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,62}$/', $configuredIdentifier) !== 1) {
            throw AuthException::invalidConfiguration(
                'The configured principal login identifier must be a canonical attribute or valid database identifier.',
            );
        }

        return $configuredIdentifier;
    }

    /** {@inheritDoc} */
    public function map(array $canonicalAttributes): array
    {
        $mapped = [];

        foreach ($canonicalAttributes as $canonical => $value) {
            $attribute = $canonical === 'emailVerified'
                ? PrincipalAttribute::EmailVerifiedAt
                : PrincipalAttribute::tryFrom($canonical);

            if (! $attribute instanceof PrincipalAttribute) {
                throw AuthException::invalidConfiguration(
                    "Unknown principal attribute [{$canonical}].",
                );
            }

            $mapped[$this->column($attribute)] = $this->normalizeMutationValue(
                $attribute,
                $canonical,
                $value,
            );
        }

        return $mapped;
    }

    public function value(User $principal, PrincipalAttribute $attribute): mixed
    {
        return $principal->getAttribute($this->column($attribute));
    }

    public function identifier(User $principal): string
    {
        $identifier = $this->value($principal, PrincipalAttribute::Id);

        if (! is_string($identifier) && ! is_int($identifier)) {
            throw AuthException::invalidConfiguration(
                'The configured principal identifier must resolve to a string or integer.',
            );
        }

        return (string) $identifier;
    }

    /**
     * @return array<string, string>
     */
    private function columns(): array
    {
        if ($this->columns !== null) {
            return $this->columns;
        }

        $configured = config('nvl-auth.features.principal_management.settings.attributes', []);

        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration(
                'Principal attribute mappings must be an array.',
            );
        }

        $columns = [];

        foreach (PrincipalAttribute::cases() as $attribute) {
            $column = $configured[$attribute->value] ?? $this->defaultColumn($attribute);

            if (! is_string($column)
                || preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,62}$/', $column) !== 1) {
                throw AuthException::invalidConfiguration(
                    "Principal attribute [{$attribute->value}] must map to a valid database identifier of at most 63 characters.",
                );
            }

            $columns[$attribute->value] = $column;
        }

        if (count(array_unique($columns)) !== count($columns)) {
            throw AuthException::invalidConfiguration(
                'Principal attributes must map to distinct database columns.',
            );
        }

        return $this->columns = $columns;
    }

    private function defaultColumn(PrincipalAttribute $attribute): string
    {
        return $attribute === PrincipalAttribute::Active
            ? 'is_active'
            : $attribute->value;
    }

    private function normalizeMutationValue(
        PrincipalAttribute $attribute,
        string $canonical,
        mixed $value,
    ): mixed {
        if ($canonical === 'emailVerified') {
            return $value === true ? now() : null;
        }

        if (! is_string($value)) {
            return $value;
        }

        return match ($attribute) {
            PrincipalAttribute::Email => mb_strtolower(trim($value)),
            PrincipalAttribute::Name,
            PrincipalAttribute::Locale,
            PrincipalAttribute::Timezone => trim($value),
            default => $value,
        };
    }
}
