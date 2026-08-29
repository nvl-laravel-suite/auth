<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthManagementAccess;

/**
 * Maps package management aliases to explicit host policy methods.
 */
final readonly class ConfiguredPolicyAuthManagementAccess implements AuthManagementAccess
{
    /**
     * Create the configured policy adapter.
     */
    public function __construct(
        private Gate $gate,
        private Repository $configuration,
        private AuthManagementAbilityCatalog $catalog,
    ) {}

    /**
     * Determine whether the host policy grants the package ability.
     */
    public function allows(
        Authenticatable $actor,
        string $ability,
        mixed $target = null,
    ): bool {
        $decision = $this->decision($ability);

        if ($decision === null) {
            return false;
        }

        $argument = $this->argument($decision['subject'], $decision['model'], $target);

        if ($argument === null) {
            return false;
        }

        return $this->gate->forUser($actor)->allows($decision['operation'], $argument);
    }

    /**
     * Determine whether one package ability has a resolvable policy decision.
     */
    public function configurationReady(string $ability): bool
    {
        $decision = $this->decision($ability);

        if ($decision === null) {
            return false;
        }

        $policy = $this->gate->getPolicyFor($decision['model']);

        return is_object($policy) && is_callable([$policy, $decision['operation']]);
    }

    /**
     * Resolve and validate one configured decision.
     *
     * @return array{operation: string, subject: 'none'|'optional'|'target', model: class-string<Model>}|null
     */
    private function decision(string $ability): ?array
    {
        $definition = $this->catalog->forAbility($ability);

        if ($definition === null) {
            return null;
        }

        if ($this->configuration->get('nvl-auth.enabled', true) !== true
            || $this->configuration->get("nvl-auth.features.{$definition['feature']->value}.enabled") !== true) {
            return null;
        }

        $abilities = $this->configuration->get('nvl-auth.management.abilities', []);
        $policyModels = $this->configuration->get('nvl-auth.management.policy_models', []);
        $operation = is_array($abilities) ? ($abilities[$definition['alias']] ?? null) : null;
        $model = is_array($policyModels) ? ($policyModels[$definition['policy']] ?? null) : null;

        if (! is_string($operation)
            || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,119}\z/', $operation) !== 1
            || ! is_string($model)
            || ! is_a($model, Model::class, true)
            || ! is_a($model, $definition['default_model'], true)) {
            return null;
        }

        /** @var class-string<Model> $model */
        return [
            'operation' => $operation,
            'subject' => $definition['subject'],
            'model' => $model,
        ];
    }

    /**
     * Build the Gate policy argument while rejecting mismatched targets.
     *
     * @param  'none'|'optional'|'target'  $subject
     * @param  class-string<Model>  $model
     */
    private function argument(string $subject, string $model, mixed $target): object|string|null
    {
        if ($subject === 'none') {
            return $model;
        }

        if ($target === null) {
            return $subject === 'optional' ? $model : null;
        }

        return $target instanceof $model ? $target : null;
    }
}
