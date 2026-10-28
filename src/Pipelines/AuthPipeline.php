<?php

declare(strict_types=1);

namespace Nvl\Auth\Pipelines;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
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
    public const NAMES = ['login', 'logout', 'password_reset_requested', 'password_reset', 'invitation_issued', 'invitation_accepted', 'client_started', 'api_token_issued', 'registration', 'profile_update', 'credential_change', 'email_change', 'social_link_change', 'impersonation_started', 'impersonation_stopped'];

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
        if (! in_array($name, self::NAMES, true) || $context->name !== $name) {
            throw AuthException::invalidConfiguration('Unknown or mismatched auth pipeline.');
        }
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
        $terminalResult = null;
        $identity = null;
        $result = (new Pipeline($this->container))
            ->send($context)
            ->through($stages)
            ->then(function (AuthPipelineContext $received) use ($terminal, $context, &$calls, &$terminalResult, &$identity): mixed {
                $calls++;
                if ($calls !== 1 || $received !== $context) {
                    throw new AuthException('pipeline_invalid', 'The native pipeline terminal must be invoked exactly once with its original context.', 422);
                }

                $terminalResult = $terminal($context);
                if ($terminalResult instanceof Model) {
                    $identity = [$terminalResult::class, $terminalResult->getConnectionName(), $terminalResult->getConnection(), $terminalResult->getTable(), $terminalResult->getKeyName(), $terminalResult->getKey(), $terminalResult->exists];
                }

                return $terminalResult;
            });
        if ($calls !== 1) {
            throw new AuthException('pipeline_invalid', 'The native pipeline terminal must be invoked exactly once.', 422);
        }

        if (! $this->sameResult($result, $terminalResult) || ($result instanceof Model && ($identity === null || $identity !== [$result::class, $result->getConnectionName(), $identity[2], $result->getTable(), $result->getKeyName(), $result->getKey(), $result->exists]))) {
            throw new AuthException('pipeline_invalid', 'A pipeline cannot substitute the native terminal result or identity.', 422);
        }
        if ($result instanceof Model && $result->getConnection() !== $identity[2]) {
            throw new AuthException('pipeline_invalid', 'A pipeline cannot change the native source.', 422);
        }

        return $result;
    }

    private function sameResult(mixed $result, mixed $nativeResult): bool
    {
        return $result === $nativeResult;
    }
}
