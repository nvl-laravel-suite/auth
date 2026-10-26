<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use LogicException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Results\GeneratedRecoveryCodes;
use Nvl\Auth\Results\TotpEnrollment;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;

/**
 * Complete native AuthSecondFactor operations.
 *
 * @api
 */
final readonly class AuthSecondFactor
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private TotpEngine $totp, private AuthAuditRecorder $audits, private AuthOperationBoundary $operations, private AuthConfiguration $configuration, private SecretHasher $hasher) {}

    /**
     * Replace prior pending enrollments and return new provisioning material once.
     *
     * Hosts must authorize and reauthenticate the owning principal before restarting.
     * Pending secrets cannot be resumed; confirmed credentials remain unchanged.
     *
     * @param  array<string, mixed>  $data
     */
    public function startEnrollment(Authenticatable $subject, array $data): TotpEnrollment
    {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Enroll);
        $data = $this->validateStartTotpEnrollment($data);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $secret = $this->totp->generateSecret();
        $parameters = $this->totp->parameters();
        $connection = (new TotpCredential)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($data, $parameters, $reference, $secret, $subject): TotpEnrollment {
            TotpCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('confirmed_at')->whereNull('revoked_at')->delete();
            $credential = TotpCredential::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'name' => $data['name'], 'secret' => $secret, ...$parameters]);
            $this->audits->record('totp.enrollment_started', subject: $reference, actor: $subject, metadata: ['credential_id' => $credential->identifier()]);

            return new TotpEnrollment($credential, $secret, $this->totp->provisioningUri($data['accountName'], $secret));
        }, 3);
    }

    /**
     * Confirm an owned pending credential.
     *
     * @param  array<string, mixed>  $data
     */
    public function confirmEnrollment(
        Authenticatable $subject,
        TotpCredential $credential,
        #[SensitiveParameter]
        array $data
    ): TotpCredential {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Enroll);
        $data = $this->validateConfirmTotpEnrollment($data);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return DB::connection($credential->getConnectionName())->transaction(function () use ($data, $credential, $reference, $subject): TotpCredential {
            /** @var TotpCredential $locked */
            $locked = TotpCredential::query()->lockForUpdate()->findOrFail($credential->identifier());
            if ($locked->subject_type !== $reference->type || $locked->subject_id !== $reference->identifier || $locked->confirmed_at !== null || $locked->revoked_at !== null) {
                throw new AuthException('totp_unavailable', 'The TOTP credential is unavailable.', 404);
            }
            $timestep = $this->totp->acceptedTimestep($locked, $data['code']);
            if ($timestep === null) {
                throw new AuthException('totp_invalid', 'The TOTP code is invalid.', 422);
            }
            $locked->forceFill(['confirmed_at' => CarbonImmutable::now(), 'last_used_at' => CarbonImmutable::now(), 'last_accepted_timestep' => $timestep])->save();
            $this->audits->record('totp.enrolled', subject: $reference, actor: $subject, metadata: ['credential_id' => $locked->identifier()]);

            return $locked;
        }, 3);
    }

    /**
     * Verify one active credential belonging to the subject.
     *
     * @param  array<string, mixed>  $data
     */
    public function verify(
        Authenticatable $subject,
        #[SensitiveParameter]
        array $data
    ): TotpCredential {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Use);
        $data = $this->validateVerifyTotp($data);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new TotpCredential)->getConnectionName();
        $result = DB::connection($connection)->transaction(function () use ($data, $reference, $subject): AuthException|TotpCredential {
            $credentials = TotpCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNotNull('confirmed_at')->whereNull('revoked_at')->lockForUpdate()->get();
            foreach ($credentials as $credential) {
                $timestep = $this->totp->acceptedTimestep($credential, $data['code']);
                if ($timestep === null) {
                    continue;
                }
                $credential->forceFill(['last_accepted_timestep' => $timestep, 'last_used_at' => CarbonImmutable::now()])->save();
                $this->audits->record('totp.verified', subject: $reference, actor: $subject, metadata: ['credential_id' => $credential->identifier()]);

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

    /**
     * Revoke an owned credential idempotently.
     */
    public function revoke(Authenticatable $subject, TotpCredential $credential): TotpCredential
    {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);
        if ($credential->subject_type !== $reference->type || $credential->subject_id !== $reference->identifier) {
            throw new AuthException('totp_unavailable', 'The TOTP credential is unavailable.', 404);
        }

        return DB::connection($credential->getConnectionName())->transaction(function () use ($credential, $reference, $subject): TotpCredential {
            /** @var TotpCredential $locked */
            $locked = TotpCredential::query()->whereKey($credential->identifier())->lockForUpdate()->firstOrFail();
            if ($locked->revoked_at === null) {
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->audits->record('totp.revoked', subject: $reference, actor: $subject, metadata: ['credential_id' => $locked->identifier()]);
            }

            return $locked;
        }, 3);
    }

    /** Return lifecycle counts for the host-authorized authenticated principal.
     * @return array<string, mixed>
     */
    public function state(Authenticatable $subject): array
    {
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Read);
        $this->operations->central(AuthIdentityOperation::Mfa, $subject);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $counts = TotpCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->toBase()->selectRaw('count(case when confirmed_at is not null and revoked_at is null then 1 end) as confirmed_credentials')->selectRaw('count(case when confirmed_at is null and revoked_at is null then 1 end) as pending_enrollments')->selectRaw('count(case when revoked_at is not null then 1 end) as revoked_credentials')->first();

        return ['confirmedCredentials' => $this->stateCount($counts->confirmed_credentials ?? null), 'pendingEnrollments' => $this->stateCount($counts->pending_enrollments ?? null), 'revokedCredentials' => $this->stateCount($counts->revoked_credentials ?? null)];
    }

    /** Normalize native aggregate integers without accepting an invalid database result. */
    private function stateCount(mixed $value): int
    {
        if (is_int($value) && $value >= 0 || is_string($value) && ctype_digit($value)) {
            return (int) $value;
        }
        throw new LogicException('TOTP lifecycle counts require nonnegative database integers.');
    }

    /**
     * Generate and persist one new recovery-code batch.
     */
    public function regenerateRecoveryCodes(Authenticatable $subject): GeneratedRecoveryCodes
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

        return DB::connection($connection)->transaction(function () use ($batchId, $codes, $reference, $subject): GeneratedRecoveryCodes {
            RecoveryCode::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('used_at')->whereNull('revoked_at')->update(['revoked_at' => CarbonImmutable::now()]);
            foreach ($codes as $code) {
                RecoveryCode::query()->create(['batch_id' => $batchId, 'subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'code_hash' => $this->hasher->hash('recovery-code', $code)]);
            }
            $this->audits->record('recovery_codes.regenerated', subject: $reference, actor: $subject, metadata: ['batch_id' => $batchId, 'count' => count($codes)]);

            return new GeneratedRecoveryCodes($batchId, $codes);
        }, 3);
    }

    /**
     * Consume one code belonging to a subject.
     *
     * @param  array<string, mixed>  $data
     */
    public function consumeRecoveryCode(
        Authenticatable $subject,
        #[SensitiveParameter]
        array $data
    ): RecoveryCode {
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Use);
        $data = $this->validateConsumeRecoveryCode($data);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new RecoveryCode)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($data, $reference, $subject): RecoveryCode {
            /** @var RecoveryCode|null $record */
            $record = RecoveryCode::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('code_hash', $this->hasher->hash('recovery-code', Str::upper(trim($data['code']))))->whereNull('used_at')->whereNull('revoked_at')->lockForUpdate()->first();
            if (! $record instanceof RecoveryCode) {
                throw new AuthException('recovery_code_invalid', 'The recovery code is invalid.', 422);
            }
            $record->forceFill(['used_at' => CarbonImmutable::now()])->save();
            $this->audits->record('recovery_code.used', subject: $reference, actor: $subject, metadata: ['batch_id' => $record->batch_id]);

            return $record;
        }, 3);
    }

    /**
     * Revoke every active code and return the affected count.
     */
    public function revokeRecoveryCodes(Authenticatable $subject): int
    {
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $connection = (new RecoveryCode)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($reference, $subject): int {
            $count = RecoveryCode::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('used_at')->whereNull('revoked_at')->update(['revoked_at' => CarbonImmutable::now()]);
            $this->audits->record('recovery_codes.revoked', subject: $reference, actor: $subject, metadata: ['count' => $count]);

            return $count;
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{code: string}
     */
    private function validateConfirmTotpEnrollment(array $data): array
    {
        if (array_diff(array_keys($data), ['code']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['code'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [code].');
        }
        Validator::make($data, ['code' => ['required', 'string', 'max:20']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{code: string}
     */
    private function validateConsumeRecoveryCode(array $data): array
    {
        if (array_diff(array_keys($data), ['code']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['code'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [code].');
        }
        Validator::make($data, ['code' => ['required', 'string', 'max:128']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{accountName: string, name: string|null}
     */
    private function validateStartTotpEnrollment(array $data): array
    {
        if (array_diff(array_keys($data), ['accountName', 'name']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['accountName'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [accountName].');
        }
        if (! array_key_exists('name', $data)) {
            $data['name'] = null;
        }
        if (! ($data['name'] === null || is_string($data['name']))) {
            throw new \InvalidArgumentException('Invalid Auth input [name].');
        }
        Validator::make($data, ['accountName' => ['required', 'string', 'max:255'], 'name' => ['nullable', 'sometimes', 'nullable', 'string', 'max:120']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{code: string}
     */
    private function validateVerifyTotp(array $data): array
    {
        if (array_diff(array_keys($data), ['code']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['code'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [code].');
        }
        Validator::make($data, ['code' => ['required', 'string', 'max:20']])->validate();

        return $data;
    }
}
