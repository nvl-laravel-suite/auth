<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedSocialRegistration;
use Nvl\Support\Events\DomainEventDispatcher;

/**
 * Server-owned verified claims and separately proved onboarding mailbox.
 *
 * @internal
 */
final readonly class SocialRegistrationContinuations
{
    public function __construct(private AuthIdentityChallenges $records, private SecretHasher $hasher, private AuthConfiguration $configuration, private AuthDeliveryContext $delivery, private DomainEventDispatcher $events) {}

    public function lock(#[\SensitiveParameter] string $secret, AuthenticationRequestContext $context): Challenge
    {
        $context->assertBound(AuthenticationDestination::Session);
        if ((new Challenge)->getConnection()->transactionLevel() === 0 || preg_match('/\A[0-9a-f]{64}\z/', $secret) !== 1) {
            throw $this->invalid();
        }
        $challenge = $this->records->query()->where('type', 'social_registration')->where('secret_hash', $this->hasher->hash('native-social-registration', $secret))->lockForUpdate()->first();
        $claims = $challenge?->payload['claims'] ?? null;
        if (! $challenge instanceof Challenge || ! $challenge->isUsable() || ($challenge->payload['context'] ?? null) !== $context->facts() || ! is_array($claims) || ! is_string($claims['provider'] ?? null) || ! is_string($claims['id'] ?? null)) {
            throw $this->invalid();
        }
        $settings = $this->configuration->get('features.social_identities.settings.providers.'.$claims['provider']);
        if (! is_array($settings) || ($settings['enabled'] ?? true) !== true || ($challenge->payload['connection'] ?? null) !== hash('sha256', json_encode($settings, JSON_THROW_ON_ERROR))) {
            throw $this->invalid();
        }

        return $challenge;
    }

    /** @return array{provider: string, id: string, email: ?string, emailVerified: bool, source: ?string, name: ?string, avatar: ?string, issuer: ?string} */
    public function claims(Challenge $challenge): array
    {
        $claims = $challenge->payload['claims'] ?? null;
        if (! is_array($claims) || ! is_string($claims['provider'] ?? null) || ! is_string($claims['id'] ?? null) || ! is_bool($claims['emailVerified'] ?? null)) {
            throw $this->invalid();
        }
        foreach (['email', 'source', 'name', 'avatar', 'issuer'] as $key) {
            if (! array_key_exists($key, $claims) || $claims[$key] !== null && ! is_string($claims[$key])) {
                throw $this->invalid();
            }
        }

        return ['provider' => $claims['provider'], 'id' => $claims['id'], 'emailVerified' => $claims['emailVerified'], 'email' => $this->optionalClaim($claims, 'email'), 'source' => $this->optionalClaim($claims, 'source'), 'name' => $this->optionalClaim($claims, 'name'), 'avatar' => $this->optionalClaim($claims, 'avatar'), 'issuer' => $this->optionalClaim($claims, 'issuer')];
    }

    /** @param array<array-key, mixed> $claims */
    private function optionalClaim(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;
        if ($value !== null && ! is_string($value)) {
            throw $this->invalid();
        }

        return $value;
    }

    /** Local mailbox proof never changes provider-email provenance. */
    public function request(#[\SensitiveParameter] string $continuation, string $email, AuthenticationRequestContext $context): void
    {
        $email = PrincipalEmailIdentity::normalize($email);
        Validator::make(['email' => $email], ['email' => ['required', 'email:rfc', 'max:254']])->validate();
        (new Challenge)->getConnection()->transaction(function () use ($continuation, $email, $context): void {
            $parent = $this->lock($continuation, $context);
            $payload = $parent->payload ?? [];
            $requests = $payload['mailboxRequests'] ?? 0;
            if (! is_int($requests) || $requests >= 5) {
                throw $this->invalid();
            }
            $this->records->query()->where('type', 'social_registration_mailbox')->where('active_key', $parent->identifier())->update(['revoked_at' => now(), 'active_key' => null]);
            $code = (string) random_int(100000, 999999);
            $expiry = CarbonImmutable::now('UTC')->addSeconds(300)->min($parent->expires_at);
            $id = (string) Str::uuid();
            $this->records->create(['type' => 'social_registration_mailbox', 'purpose' => 'registration_mailbox', 'active_key' => $parent->identifier(), 'secret_hash' => $this->hasher->hash('native-registration-mailbox-'.$id, $code), 'payload' => ['nonce' => $id, 'parent' => $parent->identifier(), 'email' => $email], 'expires_at' => $expiry, 'max_attempts' => 5]);
            $parent->payload = [...$payload, 'mailboxRequests' => $requests + 1];
            $this->records->save($parent);
            $this->events->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: AuthFeature::Registration, type: AuthMessageType::RegistrationEmailVerification, recipient: $email, payload: ['code' => $code], expiresAt: $expiry), $this->delivery->capture(true)), $parent->getConnection());
        });
    }

    public function verify(#[\SensitiveParameter] string $continuation, #[\SensitiveParameter] string $code, AuthenticationRequestContext $context): IssuedSocialRegistration
    {
        $result = (new Challenge)->getConnection()->transaction(function () use ($continuation, $code, $context): ?IssuedSocialRegistration {
            $parent = $this->lock($continuation, $context);
            $mailbox = $this->records->query()->where('type', 'social_registration_mailbox')->where('active_key', $parent->identifier())->lockForUpdate()->first();
            if ($mailbox === null || ! $mailbox->isUsable()) {
                return null;
            }
            $nonce = $mailbox->payload['nonce'] ?? null;
            if (! is_string($nonce)) {
                return null;
            }
            if (preg_match('/\A[0-9]{6}\z/', $code) !== 1 || ! hash_equals($mailbox->secret_hash, $this->hasher->hash('native-registration-mailbox-'.$nonce, $code))) {
                $mailbox->attempts++;
                $this->records->save($mailbox);

                return null;
            }
            $mailbox->consumed_at = CarbonImmutable::now();
            $mailbox->active_key = null;
            $this->records->save($mailbox);
            $parent->revoked_at = CarbonImmutable::now();
            $this->records->save($parent);
            $secret = bin2hex(random_bytes(32));
            $this->records->create(['type' => 'social_registration', 'purpose' => 'registration', 'secret_hash' => $this->hasher->hash('native-social-registration', $secret), 'payload' => [...($parent->payload ?? []), 'mailbox' => $mailbox->payload['email'] ?? null], 'expires_at' => $parent->expires_at, 'max_attempts' => 5]);

            return new IssuedSocialRegistration($secret, $parent->expires_at);
        });

        return $result ?? throw $this->invalid();
    }

    private function invalid(): AuthException
    {
        return new AuthException('social_registration_invalid', 'The social signup proof is invalid or expired.', 422);
    }
}
