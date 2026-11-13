<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AccountSecurityChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Support\SubjectReferences;
use Nvl\Auth\Support\UniqueViolation;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Auth\ValueObjects\PasskeyCredential;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use Throwable;

/**
 * Complete native AuthPasskeys operations.
 *
 * @api
 */
final readonly class AuthPasskeys
{
    use IssuesAuthenticationProofs;

    /** Create the passkey enrollment and authentication service. */
    public function __construct(private FeatureGate $features, private AuthConfiguration $configuration, private Container $container, private SecretHasher $hasher, private AuthAuditRecorder $audits, private OwnerAuthenticationChallengeIntents $ownerIntents, private PasskeyInputValidator $input, private PrincipalSecurity $security, private AuthSubjectResolver $subjects, private AuthIdentityChallenges $records, private RecentAuthenticationProofs $recent, private UsableAccountAuthenticationPolicy $nativeRemoval, private AccountAuthenticationPolicy $removalPolicy, private DomainEventDispatcher $securityEvents) {}

    /**
     * Begin one passkey authentication ceremony.
     */
    public function beginAuthentication(?Authenticatable $subject = null, ?OwnerReference $owner = null, ?string $sessionBinding = null, ?AuthenticationRequestContext $context = null): PasskeyCeremonyOptions
    {
        return $this->beginNativeAuthentication($subject, $owner, $sessionBinding, $context, AuthenticationDestination::Session);
    }

    /** Begin a subject-bound passkey ceremony exclusively for recent authentication. */
    public function beginReauthentication(Authenticatable $subject, AuthenticationRequestContext $context): PasskeyCeremonyOptions
    {
        return $this->beginNativeAuthentication($subject, null, $context->sessionBinding, $context, AuthenticationDestination::Reauthentication);
    }

    private function beginNativeAuthentication(?Authenticatable $subject, ?OwnerReference $owner, ?string $sessionBinding, ?AuthenticationRequestContext $context, AuthenticationDestination $destination): PasskeyCeremonyOptions
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Use);
        if ($context === null) {
            throw new AuthException('authentication_binding_invalid', 'A trusted authentication binding is required.', 422);
        }
        $context->assertBound($destination);
        if ($sessionBinding !== null && $sessionBinding !== $context->sessionBinding) {
            throw new AuthException('authentication_binding_invalid', 'The browser binding does not match.', 422);
        }
        $sessionBinding = $context->sessionBinding;
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
        DB::connection($connection)->transaction(function () use ($options, $reference, $subject, $owner, $sessionBinding, $context, $destination): void {
            $challenge = $this->records->create(['type' => 'passkey_authentication', 'purpose' => 'passkey_authentication', 'subject_type' => $reference?->type, 'subject_id' => $reference?->identifier, 'secret_hash' => $this->hasher->hash('passkey-ceremony', $options->ceremonyId), 'payload' => [...$options->state, '_native_context' => $context->facts(), '_native_destination' => $destination->value], 'max_attempts' => 1, 'expires_at' => $options->expiresAt]);
            $this->ownerIntents->attach($challenge, $owner, $sessionBinding, OwnerAuthenticationPurpose::PasskeyLogin, 'passkey', $reference);
            $this->audits->record('passkey.authentication_started', subject: $reference, actor: $subject, metadata: ['challenge_id' => $challenge->identifier()]);
        }, 3);

        return $options;
    }

    /**
     * Begin registration for an authenticated host subject.
     */
    public function beginRegistration(Authenticatable $subject, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): PasskeyCeremonyOptions
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Enroll);
        $this->recent->assertValid($subject, $grant, RecentAuthenticationPurpose::FactorEnrollment, $context);
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
        DB::connection($connection)->transaction(function () use ($options, $reference, $subject, $grant, $context): void {
            $this->recent->consume($subject, $grant, RecentAuthenticationPurpose::FactorEnrollment, $context);
            $challenge = $this->records->create(['type' => 'passkey_registration', 'purpose' => 'passkey_registration', 'subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'secret_hash' => $this->hasher->hash('passkey-ceremony', $options->ceremonyId), 'payload' => $options->state, 'max_attempts' => 1, 'expires_at' => $options->expiresAt]);
            $this->audits->record('passkey.registration_started', subject: $reference, actor: $subject, metadata: ['challenge_id' => $challenge->identifier()]);
        }, 3);

        return $options;
    }

    /** Verify a browser ceremony and recover only its server-owned tenant context.
     * @param  array<string, mixed>  $data
     * @return array{subject: SubjectReference, proof: IssuedAuthenticationProof, requestContext: AuthenticationRequestContext}
     */
    public function finishAuthentication(#[\SensitiveParameter] array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null): array
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Use);
        $data = $this->validateFinishPasskeyAuthentication($data);

        return $this->finishAuthenticationFinish($data, $requestedOwner, $sessionBinding);
    }

    /** Verify a passkey assertion against its stored ceremony and issue the authentication proof.
     * @param  array<string, mixed>  $data
     * @return array{subject: SubjectReference, proof: IssuedAuthenticationProof, requestContext: AuthenticationRequestContext}
     */
    private function finishAuthenticationFinish(#[\SensitiveParameter] array $data, ?OwnerReference $requestedOwner = null, ?string $sessionBinding = null): array
    {
        $data = $this->validateFinishPasskeyAuthentication($data);
        $this->input->validate($data['ceremonyId'], $data['response']);
        $connection = (new Challenge)->getConnectionName();
        $snapshot = $this->records->query()->where('type', 'passkey_authentication')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data['ceremonyId']))->first();
        if (! $snapshot instanceof Challenge || ! $snapshot->isUsable()) {
            throw new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
        }
        if (! is_array($snapshot->payload['_native_context'] ?? null) || ! in_array($snapshot->payload['_native_destination'] ?? null, [AuthenticationDestination::Session->value, AuthenticationDestination::Reauthentication->value], true)) {
            throw new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
        }
        $destination = AuthenticationDestination::from($snapshot->payload['_native_destination']);
        $nativeContext = AuthenticationRequestContext::fromFacts($snapshot->payload['_native_context']);
        $nativeContext->assertBound($destination);
        if ($nativeContext->sessionBinding !== $sessionBinding) {
            throw new AuthException('authentication_binding_invalid', 'The browser binding does not match.', 422);
        }
        $ownerContext = $this->ownerIntents->context($snapshot, $requestedOwner, $sessionBinding);
        $proofContext = $ownerContext === null ? $nativeContext : AuthenticationRequestContext::fromFacts([...$ownerContext->facts(), 'guardName' => $nativeContext->guardName, 'sessionBinding' => $nativeContext->sessionBinding]);
        $candidate = null;
        $principal = null;
        $revision = null;
        $credentialId = '';
        try {
            $credentialId = $this->ceremony()->credentialId($data['response']);
            $candidate = Passkey::query()->where('credential_id_hash', $this->hasher->hash('passkey-credential', $credentialId))->whereNull('revoked_at')->first();
            if (! $candidate instanceof Passkey || $snapshot->subject_type !== null && ($candidate->subject_type !== $snapshot->subject_type || $candidate->subject_id !== $snapshot->subject_id)) {
                throw new AuthException('passkey_invalid', 'The passkey credential is unavailable.', 422);
            }
            $principal = $this->subjects->resolve(new SubjectReference($candidate->subject_type, $candidate->subject_id));
            if ($principal === null || ! SubjectReferences::same(SubjectReference::fromAuthenticatable($principal), new SubjectReference($candidate->subject_type, $candidate->subject_id))) {
                throw new AuthException('passkey_invalid', 'The passkey credential is unavailable.', 422);
            }
            $revision = $this->security->revisionSnapshot($principal);
            $assertion = $this->ceremony()->finishAuthentication($snapshot->payload ?? [], $data['response'], new PasskeyCredential(credentialId: $candidate->credential_id, publicKey: $candidate->public_key, userHandle: $candidate->user_handle, signatureCounter: $candidate->signature_counter, backupEligible: $candidate->backup_eligible, backedUp: $candidate->backed_up));
        } catch (Throwable $exception) {
            $assertion = new AuthException('passkey_invalid', 'The passkey assertion was rejected.', 422, previous: $exception);
        }
        $result = DB::connection($connection)->transaction(function () use ($snapshot, $candidate, $principal, $revision, $credentialId, $assertion, $proofContext, $destination): array|Throwable {
            $state = $principal === null ? null : $this->security->lock($principal);
            if ($principal !== null) {
                $this->security->lockChallenges($principal);
            }
            /** @var Challenge|null $challenge */
            $challenge = $this->records->query()->whereKey($snapshot->identifier())->where('type', 'passkey_authentication')->where('secret_hash', $snapshot->secret_hash)->lockForUpdate()->first();
            if (! $challenge instanceof Challenge || ! $challenge->isUsable() || $challenge->payload !== $snapshot->payload || $challenge->subject_type !== $snapshot->subject_type || $challenge->subject_id !== $snapshot->subject_id) {
                return new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
            }
            if ($assertion instanceof Throwable) {
                $challenge->increment('attempts');

                return $assertion;
            }
            $passkey = Passkey::query()->whereKey($candidate->identifier())->whereNull('revoked_at')->lockForUpdate()->first();
            if (! $passkey instanceof Passkey || $state?->revision !== $revision
                || $passkey->subject_type !== $candidate->subject_type || $passkey->subject_id !== $candidate->subject_id
                || $passkey->credential_id !== $candidate->credential_id || $passkey->public_key !== $candidate->public_key || $passkey->user_handle !== $candidate->user_handle) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey credential is unavailable.', 422);
            }
            if (! hash_equals($credentialId, $assertion->credentialId)) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey assertion was rejected.', 422);
            }
            if (($passkey->signature_counter > 0 || $assertion->signatureCounter > 0) && $assertion->signatureCounter <= $passkey->signature_counter) {
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

            $proof = $this->issueNativeProof($principal, AuthenticationMethod::Passkey, $destination, $proofContext, $state->revision, $assertion->userVerified ? ['primary', 'user_verified'] : ['primary']);

            return ['subject' => $reference, 'proof' => $proof, 'requestContext' => $proofContext];
        }, 3);
        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /**
     * Verify browser response data and persist credential material.
     *
     * @param  array<string, mixed>  $data
     */
    public function finishRegistration(Authenticatable $subject, #[\SensitiveParameter] array $data, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): Passkey
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Enroll);
        $this->recent->assertValid($subject, $grant, RecentAuthenticationPurpose::FactorEnrollment, $context);
        $data = $this->validateFinishPasskeyRegistration($data);
        $this->input->validate($data['ceremonyId'], $data['response']);
        $this->input->validateName($data['name']);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new Challenge)->getConnectionName();
        $snapshot = $this->records->query()->where('type', 'passkey_registration')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data['ceremonyId']))->first();
        if (! $snapshot instanceof Challenge || ! $snapshot->isUsable() || $snapshot->subject_type !== $reference->type || $snapshot->subject_id !== $reference->identifier) {
            throw new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
        }
        try {
            $registration = $this->ceremony()->finishRegistration($reference, $snapshot->payload ?? [], $data['response']);
        } catch (Throwable $exception) {
            $registration = new AuthException('passkey_invalid', 'The passkey registration was rejected.', 422, previous: $exception);
        }
        try {
            $result = DB::connection($connection)->transaction(function () use ($data, $reference, $subject, $snapshot, $registration, $grant, $context): Passkey|Throwable {
                $this->recent->consume($subject, $grant, RecentAuthenticationPurpose::FactorEnrollment, $context);
                $this->security->lock($subject);
                $this->security->lockChallenges($subject);
                /** @var Challenge|null $challenge */
                $challenge = $this->records->query()->where('type', 'passkey_registration')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data['ceremonyId']))->lockForUpdate()->first();
                if (! $challenge instanceof Challenge || ! $challenge->isUsable() || $challenge->subject_type !== $reference->type || $challenge->subject_id !== $reference->identifier || $challenge->payload !== $snapshot->payload) {
                    return new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
                }
                $maximum = $this->configuration->integerBetween('features.passkeys.settings.max_credentials_per_subject', 20, 1, 100);
                $credentialCount = Passkey::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->count();
                if ($credentialCount >= $maximum) {
                    $challenge->increment('attempts');

                    return new AuthException('passkey_limit_reached', 'The passkey credential limit has been reached.', 409);
                }
                if ($registration instanceof Throwable) {
                    $challenge->increment('attempts');

                    return $registration;
                }
                $passkey = Passkey::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'name' => $data['name'], 'credential_id' => $registration->credentialId, 'credential_id_hash' => $this->hasher->hash('passkey-credential', $registration->credentialId), 'public_key' => $registration->publicKey, 'user_handle' => $registration->userHandle, 'signature_counter' => $registration->signatureCounter, 'transports' => $registration->transports, 'backup_eligible' => $registration->backupEligible, 'backed_up' => $registration->backedUp]);
                $challenge->forceFill(['consumed_at' => CarbonImmutable::now()])->save();
                $this->security->advance($subject, 'passkey_enrolled', $context);
                $this->audits->record('passkey.enrolled', subject: $reference, actor: $subject, metadata: ['passkey_id' => $passkey->identifier()]);

                return $passkey;
            }, 3);
        } catch (UniqueConstraintViolationException $exception) {
            if (UniqueViolation::columns($exception, (new Passkey)->getConnection(), (new Passkey)->getTable()) !== ['credential_id_hash']) {
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
            $challenge = $this->records->query()->where('type', 'passkey_registration')->where('secret_hash', $this->hasher->hash('passkey-ceremony', $ceremonyId))->lockForUpdate()->first();
            if ($challenge instanceof Challenge && $challenge->isUsable()) {
                $challenge->increment('attempts');
            }
        }, 3);
    }

    /**
     * Revoke an owned passkey idempotently.
     */
    public function revoke(Authenticatable $subject, Passkey $passkey, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): Passkey
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Revoke);
        $this->recent->assertValid($subject, $grant, RecentAuthenticationPurpose::FactorRemoval, $context);
        $reference = SubjectReference::fromAuthenticatable($subject);
        if ($passkey->subject_type !== $reference->type || $passkey->subject_id !== $reference->identifier) {
            throw new AuthException('passkey_unavailable', 'The passkey is unavailable.', 404);
        }

        if ($passkey->getConnection() !== (new Passkey)->getConnection()) {
            throw AuthException::invalidConfiguration('Credential mutations require the canonical source connection.');
        }

        return DB::connection($passkey->getConnectionName())->transaction(function () use ($passkey, $reference, $subject, $grant, $context): Passkey {
            $this->recent->consume($subject, $grant, RecentAuthenticationPurpose::FactorRemoval, $context);
            $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            /** @var Passkey $locked */
            $locked = Passkey::query()->whereKey($passkey->identifier())->lockForUpdate()->firstOrFail();
            if ($locked->subject_type !== $reference->type || $locked->subject_id !== $reference->identifier) {
                throw new AuthException('credential_unavailable', 'The credential is unavailable.', 422);
            }
            if ($locked->revoked_at === null) {
                $this->nativeRemoval->assertRemovalAllowed($subject, 'passkey', $locked->identifier());
                $this->removalPolicy->assertRemovalAllowed($subject, 'passkey', $locked->identifier());
                $this->nativeRemoval->assertRemovalAllowed($subject, 'passkey', $locked->identifier());
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->security->advance($subject, 'passkey_revoked', $context);
                $this->audits->record('passkey.revoked', subject: $reference, actor: $subject, metadata: ['passkey_id' => $locked->identifier()]);
                $this->securityEvents->dispatch(new AccountSecurityChanged($reference, 'passkey_revoked', $locked->identifier()), (new Passkey)->getConnection());
            }

            return $locked;
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{ceremonyId: string, response: array<string, mixed>}
     */
    private function validateFinishPasskeyAuthentication(#[\SensitiveParameter] array $data): array
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
    private function validateFinishPasskeyRegistration(#[\SensitiveParameter] array $data): array
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
