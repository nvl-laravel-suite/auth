<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use JsonSerializable;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use SensitiveParameter;

/**
 * Retains the verified credential snapshot for native finalizer freshness checks.
 *
 * @internal
 */
final readonly class AuthenticationVerification implements JsonSerializable
{
    private function __construct(public AuthenticationEvidence $evidence, #[SensitiveParameter] private ?string $passwordBinding) {}

    public static function fromChallenge(#[SensitiveParameter] Challenge $challenge): self
    {
        $evidence = AuthenticationEvidence::fromChallenge($challenge);
        $binding = $challenge->payload['passwordBinding'] ?? null;
        if ($binding !== null && ! is_string($binding) || $evidence->method === AuthenticationMethod::Password && ! is_string($binding)) {
            throw new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
        }

        return new self($evidence, $binding);
    }

    public function matchesPasswordBinding(#[SensitiveParameter] string $binding): bool
    {
        return $this->evidence->method !== AuthenticationMethod::Password
            || $this->passwordBinding !== null && hash_equals($this->passwordBinding, $binding);
    }

    /** @return array{evidence: AuthenticationEvidence, credential: string} */
    public function __debugInfo(): array
    {
        return ['evidence' => $this->evidence, 'credential' => '[REDACTED]'];
    }

    public function jsonSerialize(): never
    {
        throw new \LogicException('Authentication verification snapshots must not be serialized.');
    }

    public function __serialize(): never
    {
        throw new \LogicException('Authentication verification snapshots must not be serialized.');
    }
}
