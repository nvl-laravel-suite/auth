<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

/**
 * Centralizes package-owned RBAC read and identifier hard limits.
 *
 * @internal
 */
final readonly class RbacConsumerLimits
{
    private const int ROLE_OPTION_HARD_LIMIT = 50;

    private const int PERMISSION_OPTION_HARD_LIMIT = 100;

    private const int IDENTIFIER_RESOLUTION_HARD_LIMIT = 100;

    /**
     * Create the RBAC consumer limit policy.
     */
    public function __construct(private AuthConfiguration $configuration) {}

    /**
     * Clamp a requested role option count beneath the configured hard maximum.
     */
    public function roleOptionLimit(?int $requested = null): int
    {
        return $this->requestedLimit(
            path: 'features.rbac.settings.role_option_limit',
            default: self::ROLE_OPTION_HARD_LIMIT,
            hardMaximum: self::ROLE_OPTION_HARD_LIMIT,
            requested: $requested,
        );
    }

    /**
     * Clamp a requested permission option count beneath the configured hard maximum.
     */
    public function permissionOptionLimit(?int $requested = null): int
    {
        return $this->requestedLimit(
            path: 'features.rbac.settings.permission_option_limit',
            default: self::PERMISSION_OPTION_HARD_LIMIT,
            hardMaximum: self::PERMISSION_OPTION_HARD_LIMIT,
            requested: $requested,
        );
    }

    /**
     * Return the configured identifier resolution maximum beneath the hard cap.
     */
    public function identifierResolutionLimit(): int
    {
        return $this->configuration->integerBetween(
            'features.rbac.settings.identifier_resolution_limit',
            self::IDENTIFIER_RESOLUTION_HARD_LIMIT,
            1,
            self::IDENTIFIER_RESOLUTION_HARD_LIMIT,
        );
    }

    /**
     * Validate the configured maximum and clamp untrusted caller input.
     */
    private function requestedLimit(
        string $path,
        int $default,
        int $hardMaximum,
        ?int $requested,
    ): int {
        $configured = $this->configuration->integerBetween(
            $path,
            $default,
            1,
            $hardMaximum,
        );

        return max(1, min($requested ?? $configured, $configured));
    }
}
