<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;

/**
 * Describes one feature's dependencies, operations, and optional HTTP inventory.
 */
final readonly class FeatureDefinition
{
    /**
     * Create a feature definition.
     *
     * @param  list<FeatureOperation>  $operations
     * @param  list<AuthFeature>  $dependencies
     * @param  array<string, string>  $routeFamilies
     * @param  array<string, list<string>>  $routeNames
     * @param  array<string, list<AuthFeature>>  $routeDependencies
     * @param  list<string>  $managementAbilities
     */
    public function __construct(
        public AuthFeature $feature,
        public array $operations,
        public array $dependencies = [],
        public array $routeFamilies = [],
        public array $routeNames = [],
        public array $routeDependencies = [],
        public array $managementAbilities = [],
    ) {}

    /**
     * Determine whether the feature owns an operation.
     */
    public function supports(FeatureOperation $operation): bool
    {
        return in_array($operation, $this->operations, true);
    }

    /**
     * Return feature and route-surface dependencies without duplicates.
     *
     * @return list<AuthFeature>
     */
    public function dependenciesForSurface(string $surface): array
    {
        $dependencies = [];

        foreach ([...$this->dependencies, ...($this->routeDependencies[$surface] ?? [])] as $dependency) {
            $dependencies[$dependency->value] = $dependency;
        }

        return array_values($dependencies);
    }
}
