<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Revokes every unused recovery code for one subject.
 */
final readonly class RevokeRecoveryCodesAction
{
    /**
     * Create the recovery-code revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke every active code and return the affected count.
     */
    public function execute(Authenticatable $subject): int
    {
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new RecoveryCode)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($reference, $subject): int {
            $count = RecoveryCode::query()
                ->where('subject_type', $reference->type)
                ->where('subject_id', $reference->identifier)
                ->whereNull('used_at')
                ->whereNull('revoked_at')
                ->update(['revoked_at' => CarbonImmutable::now()]);
            $this->audits->record(
                'recovery_codes.revoked',
                subject: $reference,
                actor: $subject,
                metadata: ['count' => $count],
            );

            return $count;
        }, 3);
    }
}
