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
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Revokes one TOTP credential as a containment operation.
 */
final readonly class RevokeTotpCredentialAction
{
    /**
     * Create the TOTP revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke an owned credential idempotently.
     */
    public function execute(
        Authenticatable $subject,
        TotpCredential $credential,
    ): TotpCredential {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);

        if ($credential->subject_type !== $reference->type
            || $credential->subject_id !== $reference->identifier) {
            throw new AuthException('totp_unavailable', 'The TOTP credential is unavailable.', 404);
        }

        return DB::connection($credential->getConnectionName())->transaction(function () use ($credential, $reference, $subject): TotpCredential {
            /** @var TotpCredential $locked */
            $locked = TotpCredential::query()->whereKey($credential->identifier())->lockForUpdate()->firstOrFail();

            if ($locked->revoked_at === null) {
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->audits->record(
                    'totp.revoked',
                    subject: $reference,
                    actor: $subject,
                    metadata: ['credential_id' => $locked->identifier()],
                );
            }

            return $locked;
        }, 3);
    }
}
