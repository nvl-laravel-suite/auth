<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Data\Mutations\FinishPasskeyAuthenticationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\PasskeyInputValidator;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\PasskeyCredential;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Verifies a passkey assertion and advances its signature counter.
 */
final readonly class FinishPasskeyAuthenticationAction
{
    /**
     * Create the authentication completion use case.
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
     * Verify one browser assertion and return the owning host subject reference.
     */
    public function execute(FinishPasskeyAuthenticationData $data): SubjectReference
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Use);
        $this->input->validate($data->ceremonyId, $data->response);
        $connection = (new Challenge)->getConnectionName();

        $result = DB::connection($connection)->transaction(function () use ($data): SubjectReference|Throwable {
            /** @var Challenge|null $challenge */
            $challenge = Challenge::query()
                ->where('type', 'passkey_authentication')
                ->where('secret_hash', $this->hasher->hash('passkey-ceremony', $data->ceremonyId))
                ->lockForUpdate()
                ->first();

            if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
                return new AuthException('passkey_ceremony_invalid', 'The passkey ceremony is invalid or expired.', 422);
            }

            $state = is_array($challenge->payload) ? $challenge->payload : [];

            try {
                $credentialId = $this->ceremony->credentialId($data->response);
            } catch (Throwable $exception) {
                $challenge->increment('attempts');

                return new AuthException(
                    'passkey_invalid',
                    'The passkey assertion was rejected.',
                    422,
                    previous: $exception,
                );
            }

            /** @var Passkey|null $passkey */
            $passkey = Passkey::query()
                ->where('credential_id_hash', $this->hasher->hash('passkey-credential', $credentialId))
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $passkey instanceof Passkey
                || ($challenge->subject_type !== null
                    && ($passkey->subject_type !== $challenge->subject_type
                        || $passkey->subject_id !== $challenge->subject_id))) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey credential is unavailable.', 422);
            }

            try {
                $assertion = $this->ceremony->finishAuthentication(
                    $state,
                    $data->response,
                    new PasskeyCredential(
                        credentialId: $passkey->credential_id,
                        publicKey: $passkey->public_key,
                        userHandle: $passkey->user_handle,
                        signatureCounter: $passkey->signature_counter,
                        backupEligible: $passkey->backup_eligible,
                        backedUp: $passkey->backed_up,
                    ),
                );
            } catch (Throwable $exception) {
                $challenge->increment('attempts');

                return new AuthException(
                    'passkey_invalid',
                    'The passkey assertion was rejected.',
                    422,
                    previous: $exception,
                );
            }

            if (! hash_equals($credentialId, $assertion->credentialId)) {
                $challenge->increment('attempts');

                return new AuthException('passkey_invalid', 'The passkey assertion was rejected.', 422);
            }

            if ($passkey->signature_counter > 0
                && $assertion->signatureCounter > 0
                && $assertion->signatureCounter <= $passkey->signature_counter) {
                $challenge->increment('attempts');

                return new AuthException('passkey_counter_regression', 'The passkey assertion was rejected.', 422);
            }

            if ($assertion->backupEligible !== $passkey->backup_eligible
                || ($assertion->backedUp && ! $assertion->backupEligible)) {
                $challenge->increment('attempts');

                return new AuthException('passkey_backup_state_invalid', 'The passkey assertion was rejected.', 422);
            }

            if ($this->configuration->boolean(
                'features.passkeys.settings.require_user_verification',
                true,
            ) && ! $assertion->userVerified) {
                $challenge->increment('attempts');

                return new AuthException('passkey_user_verification_required', 'The passkey assertion was rejected.', 422);
            }

            $passkey->forceFill([
                'signature_counter' => $assertion->signatureCounter,
                'backed_up' => $assertion->backedUp,
                'last_used_at' => CarbonImmutable::now(),
            ])->save();
            $challenge->forceFill(['consumed_at' => CarbonImmutable::now()])->save();
            $reference = new SubjectReference($passkey->subject_type, $passkey->subject_id);
            $this->audits->record(
                'passkey.authenticated',
                subject: $reference,
                metadata: ['passkey_id' => $passkey->identifier(), 'user_verified' => $assertion->userVerified],
            );

            return $reference;
        }, 3);

        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }
}
