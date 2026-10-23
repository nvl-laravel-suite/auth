<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Totp;

use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;
use Nvl\Auth\Contracts\ShowTotpSecurityStateContract;
use Nvl\Auth\Data\Display\TotpSecurityStateData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Reads one authenticated principal's disjoint TOTP lifecycle counts.
 *
 * @api
 */
final readonly class ShowTotpSecurityStateAction implements ShowTotpSecurityStateContract
{
    /** Retain the feature admission and existing central identity boundary. */
    public function __construct(
        private FeatureGate $features,
        private AuthOperationBoundary $operations,
    ) {}

    /** Return lifecycle counts for the host-authorized authenticated principal. */
    public function execute(Authenticatable $subject): TotpSecurityStateData
    {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Read);
        $this->operations->central(AuthIdentityOperation::Mfa, $subject);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $counts = TotpCredential::query()
            ->where('subject_type', $reference->type)
            ->where('subject_id', $reference->identifier)
            ->toBase()
            ->selectRaw('count(case when confirmed_at is not null and revoked_at is null then 1 end) as confirmed_credentials')
            ->selectRaw('count(case when confirmed_at is null and revoked_at is null then 1 end) as pending_enrollments')
            ->selectRaw('count(case when revoked_at is not null then 1 end) as revoked_credentials')
            ->first();

        return new TotpSecurityStateData(
            confirmedCredentials: $this->count($counts->confirmed_credentials ?? null),
            pendingEnrollments: $this->count($counts->pending_enrollments ?? null),
            revokedCredentials: $this->count($counts->revoked_credentials ?? null),
        );
    }

    /** Normalize native aggregate integers without accepting an invalid database result. */
    private function count(mixed $value): int
    {
        if ((is_int($value) && $value >= 0) || (is_string($value) && ctype_digit($value))) {
            return (int) $value;
        }

        throw new LogicException('TOTP lifecycle counts require nonnegative database integers.');
    }
}
