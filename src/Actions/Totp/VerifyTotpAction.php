<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Totp;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
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
 * Verifies a TOTP proof and advances its replay cursor atomically.
 */
final readonly class VerifyTotpAction
{
    /**
     * Create the TOTP verification use case.
     */
    public function __construct(
        private FeatureGate $features,
        private TotpEngine $totp,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Verify one active credential belonging to the subject.
     */
    public function execute(
        Authenticatable $subject,
        #[SensitiveParameter] string $code,
    ): TotpCredential {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Use);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new TotpCredential)->getConnectionName();

        $result = DB::connection($connection)->transaction(function () use ($code, $reference, $subject): AuthException|TotpCredential {
            $credentials = TotpCredential::query()
                ->where('subject_type', $reference->type)
                ->where('subject_id', $reference->identifier)
                ->whereNotNull('confirmed_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->get();

            foreach ($credentials as $credential) {
                $timestep = $this->totp->acceptedTimestep($credential, $code);

                if ($timestep === null) {
                    continue;
                }

                $credential->forceFill([
                    'last_accepted_timestep' => $timestep,
                    'last_used_at' => CarbonImmutable::now(),
                ])->save();
                $this->audits->record(
                    'totp.verified',
                    subject: $reference,
                    actor: $subject,
                    metadata: ['credential_id' => $credential->identifier()],
                );

                return $credential;
            }

            $this->audits->record('totp.failed', outcome: 'failure', subject: $reference, actor: $subject);

            return new AuthException('totp_invalid', 'The TOTP code is invalid.', 422);
        }, 3);

        if ($result instanceof AuthException) {
            throw $result;
        }

        return $result;
    }
}
