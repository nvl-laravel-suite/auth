<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;

/**
 * Validated persisted native facts; never an authentication capability by itself.
 *
 * @api
 */
final readonly class AuthenticationEvidence
{
    /** @param list<string> $factors */
    private function __construct(
        public SubjectReference $subject,
        public AuthenticationMethod $method,
        public AuthenticationDestination $destination,
        public int $revision,
        public CarbonImmutable $verifiedAt,
        public CarbonImmutable $expiresAt,
        public array $factors,
        public AuthenticationRequestContext $context,
        public ?string $provider,
        #[\SensitiveParameter] public ?string $passwordBinding,
    ) {}

    /**
     * Reconstruct only after the owning service locks and validates the native proof row.
     *
     * @internal
     */
    public static function fromChallenge(Challenge $challenge): self
    {
        $facts = $challenge->payload ?? [];
        $method = is_string($facts['method'] ?? null) ? AuthenticationMethod::tryFrom($facts['method']) : null;
        $destination = is_string($facts['destination'] ?? null) ? AuthenticationDestination::tryFrom($facts['destination']) : null;
        $factors = $facts['factors'] ?? null;
        if (! is_array($factors) || ! array_is_list($factors)) {
            throw new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
        }
        foreach ($factors as $factor) {
            if (! is_string($factor)) {
                throw new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
            }
        }
        $provider = $facts['provider'] ?? null;
        $passwordBinding = $facts['passwordBinding'] ?? null;
        if ($challenge->type !== 'authentication_proof' || $method === null || $destination === null
            || $challenge->purpose !== $method->purpose()->value || ! is_string($challenge->subject_type) || ! is_string($challenge->subject_id)
            || ! is_int($facts['revision'] ?? null) || $facts['revision'] < 1 || ! is_int($facts['verifiedAt'] ?? null)
            || array_diff($factors, ['primary', 'totp', 'recovery', 'user_verified']) !== []
            || ! in_array('primary', $factors, true) || count(array_unique($factors)) !== count($factors)
            || in_array('user_verified', $factors, true) && $method !== AuthenticationMethod::Passkey
            || in_array('totp', $factors, true) && in_array('recovery', $factors, true)
            || ! is_array($facts['context'] ?? null)
            || $passwordBinding !== null && ! is_string($passwordBinding)
            || $provider !== null && ! is_string($provider)
            || $method === AuthenticationMethod::Password && ! is_string($passwordBinding)
            || $method === AuthenticationMethod::Social && ! is_string($provider)) {
            throw new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
        }
        $verified = CarbonImmutable::createFromTimestampUTC($facts['verifiedAt']);
        if ($verified->isFuture() || $challenge->expires_at->greaterThan($verified->addSeconds(300)) || $challenge->expires_at->lessThanOrEqualTo($verified)) {
            throw new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
        }
        $context = AuthenticationRequestContext::fromFacts($facts['context']);
        $context->assertBound($destination);

        return new self(new SubjectReference($challenge->subject_type, $challenge->subject_id), $method, $destination, $facts['revision'], $verified, $challenge->expires_at, $factors, $context, $provider, $passwordBinding);
    }

    public function satisfiesMfa(): bool
    {
        return in_array('totp', $this->factors, true) || in_array('recovery', $this->factors, true)
            || $this->method === AuthenticationMethod::Passkey && in_array('user_verified', $this->factors, true);
    }
}
