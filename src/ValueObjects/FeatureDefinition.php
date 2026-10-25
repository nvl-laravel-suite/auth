<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;

/**
 * Describes one feature's dependencies and native operations.
 */
final readonly class FeatureDefinition
{
    /**
     * Create a feature definition.
     *
     * @param  list<FeatureOperation>  $operations
     * @param  list<AuthFeature>  $dependencies
     * @param  list<string>  $managementAbilities
     */
    public function __construct(
        public AuthFeature $feature,
        public array $operations,
        public array $dependencies = [],
        public array $managementAbilities = [],
    ) {}

    /**
     * Determine whether the feature owns an operation.
     */
    public function supports(FeatureOperation $operation): bool
    {
        return in_array($operation, $this->operations, true);
    }
}
