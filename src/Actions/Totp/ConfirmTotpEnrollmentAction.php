<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Totp;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Data\Mutations\ConfirmTotpEnrollmentData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\TotpEngine;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;

/**
 * Confirms a pending TOTP credential with a valid non-replayed code.
 */
final readonly class ConfirmTotpEnrollmentAction
{
    /**
     * Create the TOTP confirmation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private TotpEngine $totp,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Confirm an owned pending credential.
     */
    public function execute(
        Authenticatable $subject,
        TotpCredential $credential,
        #[SensitiveParameter] ConfirmTotpEnrollmentData $data,
    ): TotpCredential {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Enroll);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return DB::connection($credential->getConnectionName())->transaction(function () use (
            $data,
            $credential,
            $reference,
            $subject,
        ): TotpCredential {
            /** @var TotpCredential $locked */
            $locked = TotpCredential::query()->lockForUpdate()->findOrFail($credential->identifier());

            if ($locked->subject_type !== $reference->type
                || $locked->subject_id !== $reference->identifier
                || $locked->confirmed_at !== null
                || $locked->revoked_at !== null) {
                throw new AuthException('totp_unavailable', 'The TOTP credential is unavailable.', 404);
            }

            $timestep = $this->totp->acceptedTimestep($locked, $data->code);

            if ($timestep === null) {
                throw new AuthException('totp_invalid', 'The TOTP code is invalid.', 422);
            }

            $locked->forceFill([
                'confirmed_at' => CarbonImmutable::now(),
                'last_used_at' => CarbonImmutable::now(),
                'last_accepted_timestep' => $timestep,
            ])->save();
            $this->audits->record(
                'totp.enrolled',
                subject: $reference,
                actor: $subject,
                metadata: ['credential_id' => $locked->identifier()],
            );

            return $locked;
        }, 3);
    }
}
