<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthenticationAssurancePolicy;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Enforces native enrolled MFA independently of optional method admission.
 *
 * @api
 */
final readonly class EnrolledFactorAssurancePolicy implements AuthenticationAssurancePolicy
{
    public function assertSatisfied(Authenticatable $subject, AuthenticationEvidence $evidence, AuthenticationPurpose $purpose): void
    {
        if ($this->requiresSecondFactor($subject) && ! $evidence->satisfiesMfa()) {
            throw new AuthException('second_factor_required', 'An enrolled second factor is required.', 422);
        }
    }

    public function requiresSecondFactor(Authenticatable $subject): bool
    {
        $model = new TotpCredential;
        if (! $model->getConnection()->getSchemaBuilder()->hasTable($model->getTable())) {
            return false;
        }
        $reference = SubjectReference::fromAuthenticatable($subject);

        return TotpCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNotNull('confirmed_at')->whereNull('revoked_at')->exists();
    }
}
