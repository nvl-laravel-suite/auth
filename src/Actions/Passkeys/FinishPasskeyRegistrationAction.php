<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Data\Mutations\FinishPasskeyRegistrationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\PasskeyInputValidator;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Finishes and persists one verified passkey registration.
 */
final readonly class FinishPasskeyRegistrationAction
{
    /**
     * Create the registration completion use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private PasskeyCeremony $ceremony,
        private SecretHasher $hasher,
        private PasskeyInputValidator $input,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Verify browser response data and persist credential material.
     */
    public function execute(
        Authenticatable $subject,
        FinishPasskeyRegistrationData $data,
    ): Passkey {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Enroll);
        $this->input->validate($data->ceremonyId, $data->response);
        $this->input->validateName($data->name);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new Challenge)->getConnectionName();

        try {
            $result = DB::connection($connection)->transaction(function () use (
                $data,
                $reference,
                $subject,
            ): Passkey|Throwable {
                /** @var Challenge|null $challenge */
                $challenge = Challenge::query()
                    ->where('type', 'passkey_registration')
                    ->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data->ceremonyId))
                    ->lockForUpdate()
                    ->first();

                if (! $challenge instanceof Challenge
                    || ! $challenge->isUsable()
                    || $challenge->subject_type !== $reference->type
                    || $challenge->subject_id !== $reference->identifier) {
                    return new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
                }

                $maximum = $this->configuration->integerBetween(
                    'features.passkeys.settings.max_credentials_per_subject',
                    20,
                    1,
                    100,
                );
                $credentialCount = Passkey::query()
                    ->where('subject_type', $reference->type)
                    ->where('subject_id', $reference->identifier)
                    ->whereNull('revoked_at')
                    ->count();

                if ($credentialCount >= $maximum) {
                    $challenge->increment('attempts');

                    return new AuthException('passkey_limit_reached', 'The passkey credential limit has been reached.', 409);
                }

                $state = is_array($challenge->payload) ? $challenge->payload : [];

                try {
                    $registration = $this->ceremony->finishRegistration($reference, $state, $data->response);
                } catch (Throwable $exception) {
                    $challenge->increment('attempts');

                    return new AuthException(
                        'passkey_invalid',
                        'The passkey registration was rejected.',
                        422,
                        previous: $exception,
                    );
                }
                $passkey = Passkey::query()->create([
                    'subject_type' => $reference->type,
                    'subject_id' => $reference->identifier,
                    'name' => $data->name,
                    'credential_id' => $registration->credentialId,
                    'credential_id_hash' => $this->hasher->hash('passkey-credential', $registration->credentialId),
                    'public_key' => $registration->publicKey,
                    'user_handle' => $registration->userHandle,
                    'signature_counter' => $registration->signatureCounter,
                    'transports' => $registration->transports,
                    'backup_eligible' => $registration->backupEligible,
                    'backed_up' => $registration->backedUp,
                ]);
                $challenge->forceFill(['consumed_at' => CarbonImmutable::now()])->save();
                $this->audits->record(
                    'passkey.enrolled',
                    subject: $reference,
                    actor: $subject,
                    metadata: ['passkey_id' => $passkey->identifier()],
                );

                return $passkey;
            }, 3);
        } catch (QueryException $exception) {
            if (! in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true)
                || (! str_contains($exception->getMessage(), 'nvl_auth_passkeys_credential_id_hash_unique')
                    && ! str_contains($exception->getMessage(), 'auth_passkeys.credential_id_hash'))) {
                throw $exception;
            }

            $this->commitFailedAttempt($connection, $data->ceremonyId);

            throw new AuthException(
                'passkey_exists',
                'The passkey credential is already registered.',
                409,
                previous: $exception,
            );
        }

        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /**
     * Commit one failed attempt after a database uniqueness conflict.
     */
    private function commitFailedAttempt(?string $connection, string $ceremonyId): void
    {
        DB::connection($connection)->transaction(function () use ($ceremonyId): void {
            /** @var Challenge|null $challenge */
            $challenge = Challenge::query()
                ->where('type', 'passkey_registration')
                ->where('secret_hash', $this->hasher->hash('passkey-ceremony', $ceremonyId))
                ->lockForUpdate()
                ->first();

            if ($challenge instanceof Challenge && $challenge->isUsable()) {
                $challenge->increment('attempts');
            }
        }, 3);
    }
}
