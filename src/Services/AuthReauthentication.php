<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Support\SubjectReferences;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedRecentAuthentication;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;
use SensitiveParameter;

/**
 * Fresh native primary/factor verification followed by a one-use operation grant.
 *
 * @api
 */
final readonly class AuthReauthentication
{
    public function __construct(private Authentication $authentication, private AuthenticationProofs $proofs, private CanonicalActorResolver $canonical, private PrincipalSecurity $security, private AuthIdentityChallenges $records, private SecretHasher $hasher, private StatefulAuthenticationBoundary $boundary, private AuthConfiguration $configuration, private AuthBrowserSessions $browserSessions) {}

    /** @param array{password?: mixed, code?: mixed, recoveryCode?: mixed, passkeyProof?: mixed, socialProof?: mixed} $proof */
    public function confirm(Authenticatable $subject, #[SensitiveParameter] array $proof, RecentAuthenticationPurpose $purpose, AuthenticationRequestContext $context): IssuedRecentAuthentication
    {
        if (! $subject instanceof Model || $subject->getConnection() !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Recent authentication requires the canonical principal source.');
        }
        $this->boundary->assertOutsideTransaction($subject->getConnection());
        $context->assertBound(AuthenticationDestination::Reauthentication);
        if ($this->configuration->featureEnabled(AuthFeature::ManagedSessions)) {
            $browser = $this->browserSessions->admit($subject, (string) $context->guardName, $context->browserBinding ?? '');
            if ($browser->identifier() !== $context->browserSessionId) {
                throw new AuthException('browser_session_invalid', 'A current admitted browser is required.', 401);
            }
        }
        if (array_diff(array_keys($proof), ['password', 'code', 'recoveryCode', 'passkeyProof', 'socialProof']) !== []
            || count(array_intersect(array_keys($proof), ['password', 'passkeyProof', 'socialProof'])) !== 1
            || isset($proof['code'], $proof['recoveryCode'])) {
            throw new \InvalidArgumentException('Exactly one native primary proof and at most one factor are required.');
        }
        foreach ($proof as $value) {
            if (! is_string($value) || $value === '' || strlen($value) > 4096) {
                throw new \InvalidArgumentException('Invalid recent authentication proof.');
            }
        }
        $subject = $this->canonical->resolve($subject);
        $password = $proof['password'] ?? null;
        $passkeyProof = $proof['passkeyProof'] ?? $proof['socialProof'] ?? null;
        if (is_string($password)) {
            $secret = $this->authentication->proveReauthentication($subject, $password, $context)->reveal();
        } elseif (is_string($passkeyProof)) {
            $secret = $passkeyProof;
        } else {
            throw new \InvalidArgumentException('A primary proof is required.');
        }
        $factor = array_intersect_key($proof, array_flip(['code', 'recoveryCode']));
        if ($factor !== []) {
            $this->proofs->completeFactor($secret, AuthenticationDestination::Reauthentication, $context, $factor);
        }
        $consumed = $this->proofs->consumeForFinalization($secret, AuthenticationDestination::Reauthentication, $context);
        $verification = $consumed['verification'];
        $evidence = $verification->evidence;
        if (! SubjectReferences::same($evidence->subject, SubjectReference::fromAuthenticatable($subject))
            || $evidence->method !== (isset($proof['password']) ? AuthenticationMethod::Password : (isset($proof['socialProof']) ? AuthenticationMethod::Social : AuthenticationMethod::Passkey))
            || $evidence->method === AuthenticationMethod::Passkey && ! in_array('user_verified', $evidence->factors, true)) {
            throw new AuthException('authentication_proof_invalid', 'The authentication proof does not match the subject.', 422);
        }
        $principal = $consumed['subject'];

        return $principal->getConnection()->transaction(function () use ($secret, $verification, $principal, $purpose): IssuedRecentAuthentication {
            $this->proofs->recheck($verification);
            $this->security->lockChallenges($principal);
            $source = $this->records->query()->where('type', 'authentication_proof')->where('secret_hash', $this->hasher->hash('native-authentication-proof', $secret))->lockForUpdate()->firstOrFail();
            $grant = bin2hex(random_bytes(32));
            $this->records->create(['type' => 'recent_authentication', 'purpose' => $purpose->value, 'subject_type' => $source->subject_type, 'subject_id' => $source->subject_id,
                'secret_hash' => $this->hasher->hash('native-recent-authentication', $grant), 'payload' => $source->payload, 'max_attempts' => 1, 'expires_at' => $source->expires_at]);

            return new IssuedRecentAuthentication($grant);
        }, 3);
    }
}
