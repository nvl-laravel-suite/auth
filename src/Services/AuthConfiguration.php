<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Config\Repository;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Reads and validates the package's canonical configuration tree.
 */
final readonly class AuthConfiguration
{
    /**
     * Create a configuration reader.
     */
    public function __construct(private Repository $config) {}

    /**
     * Determine whether functional package ingress is enabled.
     */
    public function enabled(): bool
    {
        return $this->boolean('enabled', true);
    }

    /**
     * Determine whether one feature is configured and enabled.
     */
    public function featureEnabled(AuthFeature $feature): bool
    {
        $value = $this->get("features.{$feature->value}.enabled");

        if (! is_bool($value)) {
            throw AuthException::invalidConfiguration(
                "Auth feature [{$feature->value}] must define a boolean [enabled] flag.",
            );
        }

        return $value;
    }

    /**
     * Determine whether a feature-owned route surface is enabled.
     */
    public function featureRoutesEnabled(AuthFeature $feature, string $surface): bool
    {
        return $this->boolean(
            "features.{$feature->value}.routes.{$surface}.enabled",
            false,
        );
    }

    /**
     * Read a package configuration value.
     */
    public function get(string $path, mixed $default = null): mixed
    {
        return $this->config->get("nvl-auth.{$path}", $default);
    }

    /**
     * Read a strictly boolean package configuration value.
     */
    public function boolean(string $path, bool $default = false): bool
    {
        $value = $this->get($path, $default);

        if (! is_bool($value)) {
            throw AuthException::invalidConfiguration(
                "Auth configuration [{$path}] must be boolean.",
            );
        }

        return $value;
    }

    /**
     * Read a non-empty package string.
     */
    public function string(string $path, ?string $default = null): string
    {
        $value = $this->get($path, $default);

        if (! is_string($value) || trim($value) === '') {
            throw AuthException::invalidConfiguration(
                "Auth configuration [{$path}] must be a non-empty string.",
            );
        }

        return trim($value);
    }

    /**
     * Read a positive integer package setting.
     */
    public function positiveInteger(string $path, int $default): int
    {
        $value = $this->get($path, $default);

        if (! is_int($value) || $value < 1) {
            throw AuthException::invalidConfiguration(
                "Auth configuration [{$path}] must be a positive integer.",
            );
        }

        return $value;
    }

    /**
     * Read an integer constrained to an inclusive configuration range.
     */
    public function integerBetween(string $path, int $default, int $minimum, int $maximum): int
    {
        $value = $this->get($path, $default);

        if (! is_int($value) || $value < $minimum || $value > $maximum) {
            throw AuthException::invalidConfiguration(
                "Auth configuration [{$path}] must be an integer between {$minimum} and {$maximum}.",
            );
        }

        return $value;
    }
}
