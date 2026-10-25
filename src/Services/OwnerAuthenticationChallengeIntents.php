<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Binds an owner intent to encrypted protocol state and an explicit host session binding.
 * @internal
 */
final readonly class OwnerAuthenticationChallengeIntents
{
    private const string PAYLOAD_KEY = '_owner_authentication_intent';

    public function __construct(private Container $container) {}

    public function attach(Challenge $challenge, ?OwnerReference $owner, ?string $sessionBinding, OwnerAuthenticationPurpose $purpose, string $provider, ?SubjectReference $subject = null): void
    {
        if ($owner === null) {
            return;
        }
        if ($sessionBinding === null) {
            throw AuthException::invalidConfiguration('An owner authentication ceremony requires an explicit session binding.');
        }
        $issued = $this->container->make(OwnerAuthenticationIntents::class)->issue($owner, $purpose, $sessionBinding, $subject, $provider);
        $payload = is_array($challenge->payload) ? $challenge->payload : [];
        $payload[self::PAYLOAD_KEY] = ['nonce' => $issued['nonce'], 'purpose' => $purpose->value, 'provider' => $provider, 'subject_bound' => $subject instanceof SubjectReference];
        $challenge->forceFill(['payload' => $payload])->save();
    }

    public function context(Challenge $challenge, ?OwnerReference $requestedOwner, ?string $sessionBinding): ?AuthenticationRequestContext
    {
        $payload = is_array($challenge->payload) ? $challenge->payload : [];
        $state = $payload[self::PAYLOAD_KEY] ?? null;
        if ($state === null) {
            return null;
        }
        if (! is_array($state) || ! is_string($state['nonce'] ?? null) || ! is_string($state['purpose'] ?? null) || ! is_string($state['provider'] ?? null) || ! is_bool($state['subject_bound'] ?? null)) {
            throw new AuthException('owner_authentication_intent_invalid', 'The owner authentication intent is invalid.', 410);
        }
        $purpose = OwnerAuthenticationPurpose::tryFrom($state['purpose']);
        if ($purpose === null) {
            throw new AuthException('owner_authentication_intent_invalid', 'The owner authentication intent is invalid.', 410);
        }

        return new AuthenticationRequestContext(ownerIntentNonce: $state['nonce'], ownerSessionBinding: $sessionBinding, requestedOwner: $requestedOwner, ownerPurpose: $purpose, ownerIntentSubjectBound: $state['subject_bound'], ownerProvider: $state['provider']);
    }
}
