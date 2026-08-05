<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Data\Mutations\ConsumeRecoveryCodeData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;

/**
 * Atomically consumes one recovery code.
 */
final readonly class ConsumeRecoveryCodeAction
{
    /**
     * Create the recovery-code consumption use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Consume one code belonging to a subject.
     */
    public function execute(
        Authenticatable $subject,
        #[SensitiveParameter] ConsumeRecoveryCodeData $data,
    ): RecoveryCode {
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Use);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new RecoveryCode)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($data, $reference, $subject): RecoveryCode {
            /** @var RecoveryCode|null $record */
            $record = RecoveryCode::query()
                ->where('subject_type', $reference->type)
                ->where('subject_id', $reference->identifier)
                ->where('code_hash', $this->hasher->hash('recovery-code', Str::upper(trim($data->code))))
                ->whereNull('used_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $record instanceof RecoveryCode) {
                throw new AuthException('recovery_code_invalid', 'The recovery code is invalid.', 422);
            }

            $record->forceFill(['used_at' => CarbonImmutable::now()])->save();
            $this->audits->record(
                'recovery_code.used',
                subject: $reference,
                actor: $subject,
                metadata: ['batch_id' => $record->batch_id],
            );

            return $record;
        }, 3);
    }
}
