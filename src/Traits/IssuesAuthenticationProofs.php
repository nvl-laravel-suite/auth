<?php

declare(strict_types=1);

namespace Nvl\Auth\Traits;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Private persistence shared exclusively by native verifier services.
 *
 * @internal
 */
trait IssuesAuthenticationProofs
{
    /** Native verifier supplies its captured revision and verified facts, never a public caller.
     * @param  list<string>  $factors
     */
    private function issueNativeProof(Authenticatable $subject, AuthenticationMethod $method, AuthenticationDestination $destination, AuthenticationRequestContext $context, int $revision, array $factors = ['primary'], ?string $provider = null, #[\SensitiveParameter] ?string $passwordHash = null): IssuedAuthenticationProof
    {
        $context->assertBound($destination);
        if (! $subject instanceof Model || $subject->getConnection() !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Authentication proof and principal require the same source.');
        }

        return $subject->getConnection()->transaction(function () use ($subject, $method, $destination, $context, $revision, $factors, $provider, $passwordHash): IssuedAuthenticationProof {
            $state = $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            $canonical = $subject->newQuery()->useWritePdo()->find($subject->getKey());
            if (! $canonical instanceof Authenticatable || $state->revision !== $revision
                || $passwordHash !== null && ! hash_equals($passwordHash, $canonical->getAuthPassword())) {
                throw new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
            }
            $reference = SubjectReference::fromAuthenticatable($canonical);
            $secret = bin2hex(random_bytes(32));
            $now = CarbonImmutable::now('UTC')->startOfSecond();
            $this->records->create([
                'type' => 'authentication_proof', 'purpose' => $method->purpose()->value,
                'subject_type' => $reference->type, 'subject_id' => $reference->identifier,
                'secret_hash' => $this->hasher->hash('native-authentication-proof', $secret),
                'payload' => ['method' => $method->value, 'destination' => $destination->value, 'revision' => $revision,
                    'verifiedAt' => $now->getTimestamp(), 'factors' => $factors, 'provider' => $provider,
                    'passwordBinding' => $passwordHash === null ? null : $this->hasher->hash('native-password-proof', $passwordHash),
                    'context' => $context->facts()],
                'max_attempts' => 5, 'expires_at' => $now->addSeconds(300),
            ]);

            return new IssuedAuthenticationProof($secret);
        });
    }
}
