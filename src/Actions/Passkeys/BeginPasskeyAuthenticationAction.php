<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passkeys;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Begins a discoverable or subject-scoped passkey authentication ceremony.
 */
final readonly class BeginPasskeyAuthenticationAction
{
    /**
     * Create the authentication start use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private PasskeyCeremony $ceremony,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Begin one passkey authentication ceremony.
     */
    public function execute(?Authenticatable $subject = null): PasskeyCeremonyOptions
    {
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Use);
        $reference = $subject instanceof Authenticatable
            ? SubjectReference::fromAuthenticatable($subject)
            : null;
        $credentialIds = [];

        if ($reference instanceof SubjectReference) {
            $maximum = $this->configuration->integerBetween(
                'features.passkeys.settings.max_credentials_per_subject',
                20,
                1,
                100,
            );
            $credentialIds = array_values(Passkey::query()
                ->where('subject_type', $reference->type)
                ->where('subject_id', $reference->identifier)
                ->whereNull('revoked_at')
                ->limit($maximum)
                ->get()
                ->map(static fn (Passkey $passkey): string => $passkey->credential_id)
                ->all());
        }

        try {
            $options = $this->ceremony->beginAuthentication($reference, $credentialIds);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException(
                'passkey_provider_unavailable',
                'The passkey ceremony could not be started.',
                502,
                previous: $exception,
            );
        }

        $connection = (new Challenge)->getConnectionName();
        DB::connection($connection)->transaction(function () use ($options, $reference, $subject): void {
            $challenge = Challenge::query()->create([
                'type' => 'passkey_authentication',
                'purpose' => 'passkey_authentication',
                'subject_type' => $reference?->type,
                'subject_id' => $reference?->identifier,
                'secret_hash' => $this->hasher->hash('passkey-ceremony', $options->ceremonyId),
                'payload' => $options->state,
                'max_attempts' => 1,
                'expires_at' => $options->expiresAt,
            ]);
            $this->audits->record(
                'passkey.authentication_started',
                subject: $reference,
                actor: $subject,
                metadata: ['challenge_id' => $challenge->identifier()],
            );
        }, 3);

        return $options;
    }
}
