<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Revokes one subject-owned passkey as a containment operation.
 */
final readonly class RevokePasskeyAction
{
    /**
     * Create the passkey revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke an owned passkey idempotently.
     */
    public function execute(Authenticatable $subject, Passkey $passkey): Passkey
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);

        if ($passkey->subject_type !== $reference->type || $passkey->subject_id !== $reference->identifier) {
            throw new AuthException('passkey_unavailable', 'The passkey is unavailable.', 404);
        }

        return DB::connection($passkey->getConnectionName())->transaction(function () use ($passkey, $reference, $subject): Passkey {
            /** @var Passkey $locked */
            $locked = Passkey::query()->whereKey($passkey->identifier())->lockForUpdate()->firstOrFail();

            if ($locked->revoked_at === null) {
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->audits->record(
                    'passkey.revoked',
                    subject: $reference,
                    actor: $subject,
                    metadata: ['passkey_id' => $locked->identifier()],
                );
            }

            return $locked;
        }, 3);
    }
}
