<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Support\Str;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalExtensionMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Models\User;

/**
 * Bounds host extension mapping without granting native identity authority.
 *
 * @internal
 */
final readonly class PrincipalExtensions
{
    public function __construct(private PrincipalExtensionMapper $mapper, private PrincipalAttributeMapper $attributes, private AuthModelRegistry $models) {}

    /**
     * Map within the caller's native transaction, preserving field presence.
     *
     * @param  array<array-key, mixed>  $extensions
     * @param  list<string>  $occupiedColumns
     * @return array<string, mixed>
     */
    public function map(PrincipalMutation $mutation, #[\SensitiveParameter] array $extensions, ?User $principal = null, array $occupiedColumns = []): array
    {
        $class = $this->models->userClass();
        $model = $principal ?? new $class;
        $protected = ['emailVerified', 'is_active', 'roles', 'permissions', 'revision', 'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_id', 'tenant_type', 'actor_id', 'actor_type', 'membership_id', 'is_admin', 'is_super_admin', 'extensions', $model->getKeyName(), $model->getCreatedAtColumn(), $model->getUpdatedAtColumn(), $model->getDeletedAtColumn(), $model->getRememberTokenName(), $model->getAuthPasswordName()];
        foreach (PrincipalAttribute::cases() as $attribute) {
            $protected[] = $attribute->value;
            $protected[] = $this->attributes->column($attribute);
        }
        $protected = array_values(array_filter([...$protected, ...$occupiedColumns], is_string(...)));
        $protected = [...array_map(Str::snake(...), $protected), ...array_map(strtolower(...), $protected)];
        $this->assertJson($extensions);
        $extensions = $this->validateKeys($extensions, $protected);
        $mapped = $this->mapper->validateAndMap($mutation, $extensions, $principal === null ? null : clone $principal);
        $this->assertJson($mapped);
        $mapped = $this->validateKeys($mapped, $protected);
        foreach (array_keys($mapped) as $column) {
            if (! in_array($column, $model->getFillable(), true) || ! $model->isFillable($column)) {
                throw new InvalidArgumentException('Principal extensions must map to explicitly fillable host columns.');
            }
        }

        return $mapped;
    }

    /** @param array<array-key, mixed> $values */
    private function assertJson(array $values): void
    {
        $this->assertJsonValues($values, 1);
        try {
            $encoded = json_encode($values, JSON_THROW_ON_ERROR, 16);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Principal extensions must contain bounded JSON values.', previous: $exception);
        }
        if (strlen($encoded) > 16384) {
            throw new InvalidArgumentException('Principal extensions must not exceed 16 KiB.');
        }
    }

    /** @param array<array-key, mixed> $values */
    private function assertJsonValues(array $values, int $depth): void
    {
        if ($depth > 16) {
            throw new InvalidArgumentException('Principal extension JSON depth must not exceed 16.');
        }
        foreach ($values as $value) {
            if (is_array($value)) {
                $this->assertJsonValues($value, $depth + 1);
            } elseif ($value !== null && ! is_scalar($value)) {
                throw new InvalidArgumentException('Principal extensions must contain only JSON values.');
            }
        }
    }

    /**
     * @param  array<array-key, mixed>  $values
     * @param  list<string>  $protected
     * @return array<string, mixed>
     */
    private function validateKeys(array $values, array $protected): array
    {
        $validated = [];
        foreach ($values as $key => $value) {
            if (! is_string($key) || preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,62}$/', $key) !== 1
                || in_array(Str::snake($key), $protected, true) || in_array(strtolower($key), $protected, true)
                || preg_match('/^(?:owner|ownership|security|principal_security|remember|password|totp|passkey|recovery|credential|token|impersonation|adoption)(?:_|$)/', Str::snake($key)) === 1) {
                throw new InvalidArgumentException('Principal extensions contain a protected or invalid field.');
            }
            $validated[$key] = $value;
        }

        return $validated;
    }
}
