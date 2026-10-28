<?php

declare(strict_types=1);

namespace Nvl\Auth\Pipelines;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Pipeline\Pipeline;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
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

        $hasStages = $stages !== [];
        $calls = 0;
        $terminalResult = null;
        $identity = null;
        $result = (new Pipeline($this->container))
            ->send($context)
            ->through($stages)
            ->then(function (AuthPipelineContext $received) use ($terminal, $context, $hasStages, &$calls, &$terminalResult, &$identity): mixed {
                $calls++;
                if ($calls !== 1 || $received !== $context) {
                    throw new AuthException('pipeline_invalid', 'The native pipeline terminal must be invoked exactly once with its original context.', 422);
                }

                $terminalResult = $terminal($context);
                $identity = $hasStages ? $this->identitySnapshot($terminalResult) : null;

                return $terminalResult;
            });
        if ($calls !== 1) {
            throw new AuthException('pipeline_invalid', 'The native pipeline terminal must be invoked exactly once.', 422);
        }

        if (! $this->sameResult($result, $terminalResult) || $hasStages && $identity !== $this->identitySnapshot($result)) {
            throw new AuthException('pipeline_invalid', 'A pipeline cannot substitute native results or protected identities.', 422);
        }

        return $result;
    }

    /** Capture immutable identity metadata recursively, including models inside result arrays. */
    private function identitySnapshot(#[\SensitiveParameter] mixed $result): mixed
    {
        if (is_array($result)) {
            $snapshot = [];
            foreach ($result as $key => $value) {
                $snapshot[$key] = $this->identitySnapshot($value);
            }

return $snapshot;
        }
        if (! $result instanceof Model) {
            return null;
        }
        try {
            $protected = array_intersect_key($result->getAttributes(), array_flip(['subject_type', 'subject_id', 'actor_type', 'actor_id', 'effective_subject_type', 'effective_subject_id', 'browser_session_id', 'guard_name', 'provider', 'provider_user_id_hash', 'credential_id_hash', 'tokenable_type', 'tokenable_id', 'owner_scope_key', 'owner_reference', 'security_revision']));
            $principal = $result instanceof Authenticatable ? [$result->getAuthPassword(), $result->getRememberToken()] : null;
            if ($result instanceof User) {
                $principal = [$principal, $result->getEmailForVerification(), $result->hasVerifiedEmail(), $result->isAuthenticationAllowed()];
                if ($result->exists) {
                    $fresh = $result->newQuery()->useWritePdo()->find($result->getKey());
                    if (! $fresh instanceof User) {
                        throw new AuthException('pipeline_invalid', 'The native principal disappeared during a callback.', 422);
                    }
                    $principal[] = [$fresh->getAuthPassword(), $fresh->getRememberToken(), $fresh->getEmailForVerification(), $fresh->hasVerifiedEmail(), $fresh->isAuthenticationAllowed()];
                }
            }

            return [$result::class, $result->getConnectionName(), $result->getConnection(), $result->getTable(), $result->getKeyName(), $result->getKey(), $result->exists, $protected, $principal];
        } catch (\Throwable) {
            throw new AuthException('pipeline_invalid', 'A pipeline cannot change native identity storage.', 422);
        }
    }

    private function sameResult(mixed $result, mixed $nativeResult): bool
    {
        return $result === $nativeResult;
    }
}
