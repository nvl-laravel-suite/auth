<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Enforces package ingress, feature flags, operation ownership, and dependencies.
 */
final readonly class FeatureGate
{
    /**
     * Create the package admission gate.
     */
    public function __construct(
        private AuthConfiguration $configuration,
        private FeatureManifest $manifest,
    ) {}

    /**
     * Determine whether a feature operation is admitted.
     */
    public function allows(AuthFeature $feature, FeatureOperation $operation): bool
    {
        $definition = $this->manifest->definition($feature);

        if (! $definition->supports($operation)) {
            return false;
        }

        if ($operation->isContainment()) {
            return true;
        }

        if (! $this->configuration->enabled() || ! $this->configuration->featureEnabled($feature)) {
            return false;
        }

        foreach ($definition->dependencies as $dependency) {
            if (! $this->configuration->featureEnabled($dependency)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Require a feature operation before any query or side effect.
     */
    public function assertAllowed(AuthFeature $feature, FeatureOperation $operation): void
    {
        if ($this->allows($feature, $operation)) {
            return;
        }

        $missing = [];

        foreach ($this->manifest->definition($feature)->dependencies as $dependency) {
            if (! $this->configuration->featureEnabled($dependency)) {
                $missing[] = $dependency->value;
            }
        }

        throw AuthException::featureUnavailable($feature, $operation, $missing);
    }
}
