<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\OwnerAuthenticationIntent;
use Nvl\Auth\ValueObjects\IssuedOwnerAuthenticationIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnerAvailability;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipInstallationState;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use stdClass;

/**
 * Issues browser-bound owner selection proofs without admitting an owner or creating membership.
 * Its bounded raw source writes are restricted to this secret-bearing protocol, never arbitrary resources.
 *
 * @api
 */
final readonly class OwnerAuthenticationIntents
{
    public function __construct(private SecretHasher $hasher, private OpaqueTokenFactory $tokens, private OwnerIdentityResolver $owners, private OwnerAvailability $availability, private OwnershipInstallationState $installation, private OwnershipReadiness $readiness) {}

    /** Return a nonce once after verifying a canonical available owner. */
    public function issue(OwnerReference $owner, OwnerAuthenticationPurpose $purpose, string $sessionBinding, ?SubjectReference $subject = null): IssuedOwnerAuthenticationIntent
    {
        $this->validateBinding($sessionBinding);
        $this->assertAvailable($owner);
        $nonce = $this->tokens->make();
        $id = (string) Str::uuid();
        $expires = CarbonImmutable::instance(now())->addMinutes(10);
        $model = new OwnerAuthenticationIntent;
        $model->forceFill([
            'id' => $id, 'owner_scope_key' => $owner->scopeKey(), 'owner_reference' => json_encode($owner->toArray(), JSON_THROW_ON_ERROR),
            'purpose' => $purpose->value, 'nonce_hash' => $this->hasher->hash('owner-authentication-intent', $nonce),
            'session_binding_hash' => $this->hasher->hash('owner-authentication-session', $sessionBinding),
            'subject_type' => $subject?->type, 'subject_id' => $subject?->identifier,
            'payload' => ['generations' => $this->installation->generations()], 'expires_at' => $expires,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $model->getConnection()->table($model->getTable())->insert($model->getAttributes());

        return new IssuedOwnerAuthenticationIntent($id, $nonce, $expires);
    }

    /** Consume a matching proof atomically; the caller must still authorize owner entry independently. */
    public function consume(string $nonce, OwnerAuthenticationPurpose $purpose, string $sessionBinding, OwnerReference $expectedOwner, ?SubjectReference $subject = null): OwnerReference
    {
        $this->validateBinding($sessionBinding);
        $this->assertAvailable($expectedOwner);
        $model = new OwnerAuthenticationIntent;

        return $model->getConnection()->transaction(function () use ($model, $nonce, $purpose, $sessionBinding, $expectedOwner, $subject): OwnerReference {
            $query = $model->getConnection()->table($model->getTable())->useWritePdo()->where('nonce_hash', $this->hasher->hash('owner-authentication-intent', $nonce));
            $row = $query->lockForUpdate()->first();
            if (! $row instanceof stdClass) {
                throw $this->invalid();
            }
            $intent = $model->newFromBuilder(AuthStoredRow::attributes($row));
            $payload = $intent->getAttribute('payload');
            if (! is_string($row->expires_at) || ! is_string($row->owner_reference) || ! is_string($row->session_binding_hash)
                || $row->consumed_at !== null || CarbonImmutable::parse($row->expires_at)->isPast()
                || $row->purpose !== $purpose->value || $row->owner_scope_key !== $expectedOwner->scopeKey()
                || OwnerReference::fromJson($row->owner_reference) != $expectedOwner
                || ! hash_equals($row->session_binding_hash, $this->hasher->hash('owner-authentication-session', $sessionBinding))
                || $row->subject_type !== $subject?->type || $row->subject_id !== $subject?->identifier
                || ! is_array($payload) || ($payload['generations'] ?? null) !== $this->installation->generations()) {
                throw $this->invalid();
            }
            if ($query->whereNull('consumed_at')->update(['consumed_at' => now(), 'updated_at' => now()]) !== 1) {
                throw $this->invalid();
            }

            return $expectedOwner;
        }, 3);
    }

    private function assertAvailable(OwnerReference $owner): void
    {
        $this->readiness->assertActive('auth.authentication_intents');
        $this->availability->assertAvailable($this->owners->resolve($owner));
    }

    private function validateBinding(string $binding): void
    {
        if ($binding === '' || $binding !== trim($binding) || strlen($binding) > 512) {
            throw new InvalidArgumentException('Owner selection requires a bounded browser session binding.');
        }
    }

    private function invalid(): AuthException
    {
        return new AuthException('owner_authentication_intent_invalid', 'The owner authentication intent is invalid.', 410);
    }
}
