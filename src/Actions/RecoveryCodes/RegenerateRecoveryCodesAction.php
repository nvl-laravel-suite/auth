<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Results\GeneratedRecoveryCodes;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Revokes existing recovery codes and issues one new one-time batch.
 */
final readonly class RegenerateRecoveryCodesAction
{
    /**
     * Create the recovery-code regeneration use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Generate and persist one new recovery-code batch.
     */
    public function execute(Authenticatable $subject): GeneratedRecoveryCodes
    {
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Issue);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $count = $this->configuration->integerBetween('features.recovery_codes.settings.count', 8, 1, 100);
        $length = $this->configuration->integerBetween('features.recovery_codes.settings.length', 10, 8, 128);
        $batchId = (string) Str::uuid();
        $codes = [];

        for ($index = 0; $index < $count; $index++) {
            $codes[] = Str::upper(Str::random($length));
        }

        $connection = (new RecoveryCode)->getConnectionName();

        return DB::connection($connection)->transaction(function () use (
            $batchId,
            $codes,
            $reference,
            $subject,
        ): GeneratedRecoveryCodes {
            RecoveryCode::query()
                ->where('subject_type', $reference->type)
                ->where('subject_id', $reference->identifier)
                ->whereNull('used_at')
                ->whereNull('revoked_at')
                ->update(['revoked_at' => CarbonImmutable::now()]);

            foreach ($codes as $code) {
                RecoveryCode::query()->create([
                    'batch_id' => $batchId,
                    'subject_type' => $reference->type,
                    'subject_id' => $reference->identifier,
                    'code_hash' => $this->hasher->hash('recovery-code', $code),
                ]);
            }

            $this->audits->record(
                'recovery_codes.regenerated',
                subject: $reference,
                actor: $subject,
                metadata: ['batch_id' => $batchId, 'count' => count($codes)],
            );

            return new GeneratedRecoveryCodes($batchId, $codes);
        }, 3);
    }
}
