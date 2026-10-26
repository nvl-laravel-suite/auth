<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Auth\ValueObjects\PasskeyCredential;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use Throwable;

/**
 * Complete native AuthPasskeys operations.
 *
 * @api
 */
final readonly class AuthPasskeys
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthConfiguration $configuration, private Container $container, private SecretHasher $hasher, private AuthAuditRecorder $audits, private OwnerAuthenticationChallengeIntents $ownerIntents, private PasskeyInputValidator $input) {}

    /**
     * Begin one passkey authentication ceremony.
     */
    public function beginAuthentication(?Authenticatable $subject = null, ?OwnerReference $owner = null, ?string $sessionBinding = null): PasskeyCeremonyOptions
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Use);
        $reference = $subject instanceof Authenticatable ? SubjectReference::fromAuthenticatable($subject) : null;
        $credentialIds = [];
        if ($reference instanceof SubjectReference) {
            $maximum = $this->configuration->integerBetween('features.passkeys.settings.max_credentials_per_subject', 20, 1, 100);
            $credentialIds = array_values(Passkey::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->limit($maximum)->get()->map(static fn (Passkey $passkey): string => $passkey->credential_id)->all());
        }
        try {
            $options = $this->ceremony()->beginAuthentication($reference, $credentialIds);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException('passkey_provider_unavailable', 'The passkey ceremony could not be started.', 502, previous: $exception);
        }
        $connection = (new Challenge)->getConnectionName();
        DB::connection($connection)->transaction(function () use ($options, $reference, $subject, $owner, $sessionBinding): void {
            $challenge = Challenge::query()->create(['type' => 'passkey_authentication', 'purpose' => 'passkey_authentication', 'subject_type' => $reference?->type, 'subject_id' => $reference?->identifier, 'secret_hash' => $this->hasher->hash('passkey-ceremony', $options->ceremonyId), 'payload' => $options->state, 'max_attempts' => 1, 'expires_at' => $options->expiresAt]);
            $this->ownerIntents->attach($challenge, $owner, $sessionBinding, OwnerAuthenticationPurpose::PasskeyLogin, 'passkey', $reference);
            $this->audits->record('passkey.authentication_started', subject: $reference, actor: $subject, metadata: ['challenge_id' => $challenge->identifier()]);
        }, 3);

        return $options;
    }

    /**
     * Begin registration for an authenticated host subject.
     */
    public function beginRegistration(Authenticatable $subject): PasskeyCeremonyOptions
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Enroll);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $maximum = $this->configuration->integerBetween('features.passkeys.settings.max_credentials_per_subject', 20, 1, 100);
        $passkeys = Passkey::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->limit($maximum + 1)->get();
        if ($passkeys->count() >= $maximum) {
            throw new AuthException('passkey_limit_reached', 'The passkey credential limit has been reached.', 409);
        }
        $credentialIds = array_values($passkeys->map(static fn (Passkey $passkey): string => $passkey->credential_id)->all());
        try {
            $options = $this->ceremony()->beginRegistration($subject, $reference, $credentialIds);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException('passkey_provider_unavailable', 'The passkey ceremony could not be started.', 502, previous: $exception);
        }
        $connection = (new Challenge)->getConnectionName();
        DB::connection($connection)->transaction(function () use ($options, $reference, $subject): void {
            $challenge = Challenge::query()->create(['type' => 'passkey_registration', 'purpose' => 'passkey_registration', 'subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'secret_hash' => $this->hasher->hash('passkey-ceremony', $options->ceremonyId), 'payload' => $options->state, 'max_attempts' => 1, 'expires_at' => $options->expiresAt]);
            $this->audits->record('passkey.registration_started', subject: $reference, actor: $subject, metadata: ['challenge_id' => $challenge->identifier()]);
        }, 3);

        return $options;
    }

    /** Verify a browser ceremony and recover only its server-owned tenant context.
     * @param  array<string, mixed>  $data
     * @return array{subject: SubjectReference, requestContext: AuthenticationRequestContext|null}
     */
    public function finishAuthentication(array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null): array
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Use);
        $data = $this->validateFinishPasskeyAuthentication($data);

        return $this->finishAuthenticationFinish($data, $requestedOwner, $sessionBinding);
    }

    /** Native Auth operation.
     * @param  array<string, mixed>  $data
     * @return array{subject: SubjectReference, requestContext: AuthenticationRequestContext|null}
     */
    private function finishAuthenticationFinish(array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null): array
    {
        $data = $this->validateFinishPasskeyAuthentication($data);
        $this->input->validate($data['ceremonyId'], $data['response']);
        $connection = (new Challenge)->getConnectionName();
        $result = DB::connection($connection)->transaction(function () use ($data): array|Throwable {
            /** @var Challenge|null $challenge */
            $challenge = Challenge::query()->where('type', 'passkey_authentication')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data['ceremonyId']))->lockForUpdate()->first();
            if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
                return new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
            }
            $state = is_array($challenge->payload) ? $challenge->payload : [];
            try {
                $credentialId = $this->ceremony()->credentialId($data['response']);
            } catch (Throwable $exception) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey assertion was rejected.', 422, previous: $exception);
            }
            /** @var Passkey|null $passkey */
            $passkey = Passkey::query()->where('credential_id_hash', $this->hasher->hash('passkey-credential', $credentialId))->whereNull('revoked_at')->lockForUpdate()->first();
            if (! $passkey instanceof Passkey || $challenge->subject_type !== null && ($passkey->subject_type !== $challenge->subject_type || $passkey->subject_id !== $challenge->subject_id)) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey credential is unavailable.', 422);
            }
            try {
                $assertion = $this->ceremony()->finishAuthentication($state, $data['response'], new PasskeyCredential(credentialId: $passkey->credential_id, publicKey: $passkey->public_key, userHandle: $passkey->user_handle, signatureCounter: $passkey->signature_counter, backupEligible: $passkey->backup_eligible, backedUp: $passkey->backed_up));
            } catch (Throwable $exception) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey assertion was rejected.', 422, previous: $exception);
            }
            if (! hash_equals($credentialId, $assertion->credentialId)) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey assertion was rejected.', 422);
            }
            if ($passkey->signature_counter > 0 && $assertion->signatureCounter > 0 && $assertion->signatureCounter <= $passkey->signature_counter) {
                $challenge->increment('attempts');

                return new AuthException('passkey_counter_regression', 'The passkey assertion was rejected.', 422);
            }
            if ($assertion->backupEligible !== $passkey->backup_eligible || $assertion->backedUp && ! $assertion->backupEligible) {
                $challenge->increment('attempts');

                return new AuthException('passkey_backup_state_invalid', 'The passkey assertion was rejected.', 422);
            }
            if ($this->configuration->boolean('features.passkeys.settings.require_user_verification', true) && ! $assertion->userVerified) {
                $challenge->increment('attempts');

                return new AuthException('passkey_user_verification_required', 'The passkey assertion was rejected.', 422);
            }
            $passkey->forceFill(['signature_counter' => $assertion->signatureCounter, 'backed_up' => $assertion->backedUp, 'last_used_at' => CarbonImmutable::now()])->save();
            $challenge->forceFill(['consumed_at' => CarbonImmutable::now()])->save();
            $reference = new SubjectReference($passkey->subject_type, $passkey->subject_id);
            $this->audits->record('passkey.authenticated', subject: $reference, metadata: ['passkey_id' => $passkey->identifier(), 'user_verified' => $assertion->userVerified]);

            return ['subject' => $reference, 'challenge' => $challenge];
        }, 3);
        if ($result instanceof Throwable) {
            throw $result;
        }

        return ['subject' => $result['subject'], 'requestContext' => $this->ownerIntents->context($result['challenge'], $requestedOwner, $sessionBinding)];
    }

    /**
     * Verify browser response data and persist credential material.
     *
     * @param  array<string, mixed>  $data
     */
    public function finishRegistration(Authenticatable $subject, array $data): Passkey
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Enroll);
        $data = $this->validateFinishPasskeyRegistration($data);
        $this->input->validate($data['ceremonyId'], $data['response']);
        $this->input->validateName($data['name']);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new Challenge)->getConnectionName();
        try {
            $result = DB::connection($connection)->transaction(function () use ($data, $reference, $subject): Passkey|Throwable {
                /** @var Challenge|null $challenge */
                $challenge = Challenge::query()->where('type', 'passkey_registration')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data['ceremonyId']))->lockForUpdate()->first();
                if (! $challenge instanceof Challenge || ! $challenge->isUsable() || $challenge->subject_type !== $reference->type || $challenge->subject_id !== $reference->identifier) {
                    return new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
                }
                $maximum = $this->configuration->integerBetween('features.passkeys.settings.max_credentials_per_subject', 20, 1, 100);
                $credentialCount = Passkey::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->count();
                if ($credentialCount >= $maximum) {
                    $challenge->increment('attempts');

                    return new AuthException('passkey_limit_reached', 'The passkey credential limit has been reached.', 409);
                }
                $state = is_array($challenge->payload) ? $challenge->payload : [];
                try {
                    $registration = $this->ceremony()->finishRegistration($reference, $state, $data['response']);
                } catch (Throwable $exception) {
                    $challenge->increment('attempts');

                    return new AuthException('passkey_invalid', 'The passkey registration was rejected.', 422, previous: $exception);
                }
                $passkey = Passkey::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'name' => $data['name'], 'credential_id' => $registration->credentialId, 'credential_id_hash' => $this->hasher->hash('passkey-credential', $registration->credentialId), 'public_key' => $registration->publicKey, 'user_handle' => $registration->userHandle, 'signature_counter' => $registration->signatureCounter, 'transports' => $registration->transports, 'backup_eligible' => $registration->backupEligible, 'backed_up' => $registration->backedUp]);
                $challenge->forceFill(['consumed_at' => CarbonImmutable::now()])->save();
                $this->audits->record('passkey.enrolled', subject: $reference, actor: $subject, metadata: ['passkey_id' => $passkey->identifier()]);

                return $passkey;
            }, 3);
        } catch (QueryException $exception) {
            if (! in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true) || ! str_contains($exception->getMessage(), 'nvl_auth_passkeys_credential_id_hash_unique') && ! str_contains($exception->getMessage(), 'auth_passkeys.credential_id_hash')) {
                throw $exception;
            }
            $this->finishRegistrationCommitFailedAttempt($connection, $data['ceremonyId']);
            throw new AuthException('passkey_exists', 'The passkey credential is already registered.', 409, previous: $exception);
        }
        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /**
     * Commit one failed attempt after a database uniqueness conflict.
     */
    private function finishRegistrationCommitFailedAttempt(?string $connection, string $ceremonyId): void
    {
        DB::connection($connection)->transaction(function () use ($ceremonyId): void {
            /** @var Challenge|null $challenge */
            $challenge = Challenge::query()->where('type', 'passkey_registration')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $ceremonyId))->lockForUpdate()->first();
            if ($challenge instanceof Challenge && $challenge->isUsable()) {
                $challenge->increment('attempts');
            }
        }, 3);
    }

    /**
     * Revoke an owned passkey idempotently.
     */
    public function revoke(Authenticatable $subject, Passkey $passkey): Passkey
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);
        if ($passkey->subject_type !== $reference->type || $passkey->subject_id !== $reference->identifier) {
            throw new AuthException('passkey_unavailable', 'The passkey is unavailable.', 404);
        }

        return DB::connection($passkey->getConnectionName())->transaction(function () use ($passkey, $reference, $subject): Passkey {
            /** @var Passkey $locked */
            $locked = Passkey::query()->whereKey($passkey->identifier())->lockForUpdate()->firstOrFail();
            if ($locked->revoked_at === null) {
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->audits->record('passkey.revoked', subject: $reference, actor: $subject, metadata: ['passkey_id' => $locked->identifier()]);
            }

            return $locked;
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{ceremonyId: string, response: array<string, mixed>}
     */
    private function validateFinishPasskeyAuthentication(array $data): array
    {
        if (array_diff(array_keys($data), ['ceremonyId', 'response']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['ceremonyId'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [ceremonyId].');
        }
        if (! is_array($data['response'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [response].');
        }
        $data['response'] = $this->responseFields($data['response']);
        Validator::make($data, ['response' => ['required', 'array']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{ceremonyId: string, response: array<string, mixed>, name: string|null}
     */
    private function validateFinishPasskeyRegistration(array $data): array
    {
        if (array_diff(array_keys($data), ['ceremonyId', 'response', 'name']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['ceremonyId'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [ceremonyId].');
        }
        if (! is_array($data['response'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [response].');
        }
        $data['response'] = $this->responseFields($data['response']);
        if (! array_key_exists('name', $data)) {
            $data['name'] = null;
        }
        if (! ($data['name'] === null || is_string($data['name']))) {
            throw new \InvalidArgumentException('Invalid Auth input [name].');
        }
        Validator::make($data, ['ceremonyId' => ['required', 'string', 'max:191'], 'response' => ['required', 'array'], 'name' => ['nullable', 'sometimes', 'nullable', 'string', 'max:120']])->validate();

        return $data;
    }

    /** Resolve the selected engine only after feature admission. */
    private function ceremony(): PasskeyCeremony
    {
        return $this->container->make(PasskeyCeremony::class);
    }

    /** @param array<array-key, mixed> $response
     * @return array<string, mixed>
     */
    private function responseFields(array $response): array
    {
        $fields = [];
        foreach ($response as $key => $value) {
            if (! is_string($key)) {
                throw new \InvalidArgumentException('Passkey response fields must be named.');
            }
            $fields[$key] = $value;
        }

        return $fields;
    }
}
