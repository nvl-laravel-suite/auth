<?php

declare(strict_types=1);

namespace Nvl\Auth\Pipelines;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Pipeline\Pipeline;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\ValueObjects\AuthPipelineContext;

/**
 * Executes host-configured stages around package-owned use cases.
 */
final readonly class AuthPipeline
{
    /**
     * Create the named pipeline runner.
     */
    public function __construct(
        private Container $container,
        private AuthConfiguration $configuration,
    ) {}

    /**
     * Run one configured pipeline and return its terminal result.
     *
     * @template TResult
     *
     * @param  Closure(AuthPipelineContext): TResult  $terminal
     * @return TResult
     */
    public function run(
        string $name,
        AuthPipelineContext $context,
        Closure $terminal,
    ): mixed {
        $configured = $this->configuration->get("pipelines.{$name}", []);

        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration("Auth pipeline [{$name}] must be an array.");
        }

        $stages = [];

        foreach ($configured as $stage) {
            if (! is_string($stage) || ! is_a($stage, AuthPipelineStage::class, true)) {
                throw AuthException::invalidConfiguration(
                    "Auth pipeline [{$name}] contains an invalid stage.",
                );
            }

            $stages[] = $stage;
        }

        $calls = 0;
        $result = (new Pipeline($this->container))
            ->send($context)
            ->through($stages)
            ->then(function (AuthPipelineContext $received) use ($terminal, $context, &$calls): mixed {
                $calls++;
                if ($calls !== 1 || $received !== $context) {
                    throw new AuthException('pipeline_invalid', 'The native pipeline terminal must be invoked exactly once with its original context.', 422);
                }

                return $terminal($context);
            });
        if ($calls !== 1) {
            throw new AuthException('pipeline_invalid', 'The native pipeline terminal must be invoked exactly once.', 422);
        }

        return $result;
    }
}
