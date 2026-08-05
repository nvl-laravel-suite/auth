<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Totp;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Results\TotpEnrollment;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\TotpEngine;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Starts one encrypted TOTP enrollment.
 */
final readonly class StartTotpEnrollmentAction
{
    /**
     * Create the TOTP enrollment use case.
     */
    public function __construct(
        private FeatureGate $features,
        private TotpEngine $totp,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Create a pending TOTP credential and return its one-time secret.
     */
    public function execute(
        Authenticatable $subject,
        StartTotpEnrollmentData $data,
    ): TotpEnrollment {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Enroll);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $secret = $this->totp->generateSecret();
        $parameters = $this->totp->parameters();
        $connection = (new TotpCredential)->getConnectionName();

        return DB::connection($connection)->transaction(function () use (
            $data,
            $parameters,
            $reference,
            $secret,
            $subject,
        ): TotpEnrollment {
            TotpCredential::query()
                ->where('subject_type', $reference->type)
                ->where('subject_id', $reference->identifier)
                ->whereNull('confirmed_at')
                ->delete();
            $credential = TotpCredential::query()->create([
                'subject_type' => $reference->type,
                'subject_id' => $reference->identifier,
                'name' => $data->name,
                'secret' => $secret,
                ...$parameters,
            ]);
            $this->audits->record(
                'totp.enrollment_started',
                subject: $reference,
                actor: $subject,
                metadata: ['credential_id' => $credential->identifier()],
            );

            return new TotpEnrollment(
                $credential,
                $secret,
                $this->totp->provisioningUri($data->accountName, $secret),
            );
        }, 3);
    }
}
