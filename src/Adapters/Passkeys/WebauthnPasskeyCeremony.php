<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\ValueObjects\PasskeyAssertion;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Auth\ValueObjects\PasskeyCredential;
use Nvl\Auth\ValueObjects\PasskeyRegistration;
use Nvl\Auth\ValueObjects\SubjectReference;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Runs production WebAuthn ceremonies while NVL Auth owns lifecycle and persistence.
 */
final class WebauthnPasskeyCeremony implements PasskeyCeremony
{
    private const STATE_VERSION = 1;

    private const REGISTRATION = 'registration';

    private const AUTHENTICATION = 'authentication';

    private readonly DenormalizerInterface&NormalizerInterface $serializer;

    private readonly AuthenticatorAttestationResponseValidator $registrationValidator;

    private readonly AuthenticatorAssertionResponseValidator $authenticationValidator;

    /**
     * Create the maintained WebAuthn adapter from package configuration.
     */
    public function __construct(
        private readonly AuthConfiguration $configuration,
        private readonly Repository $applicationConfiguration,
    ) {
        $attestationStatements = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport,
        ]);
        $ceremonies = new CeremonyStepManagerFactory;
        $ceremonies->setAttestationStatementSupportManager($attestationStatements);
        $ceremonies->setAllowedOrigins($this->origins(), $this->allowSubdomains());
        $ceremonies->setCounterChecker(new DeferPasskeyCounterPolicy);
        $serializer = (new WebauthnSerializerFactory($attestationStatements))->create();

        if (! $serializer instanceof DenormalizerInterface || ! $serializer instanceof NormalizerInterface) {
            throw AuthException::invalidConfiguration(
                'The WebAuthn serializer must normalize and denormalize ceremony data.',
            );
        }

        $this->serializer = $serializer;
        $this->registrationValidator = AuthenticatorAttestationResponseValidator::create(
            $ceremonies->creationCeremony(),
        );
        $this->authenticationValidator = AuthenticatorAssertionResponseValidator::create(
            $ceremonies->requestCeremony(),
        );
    }

    /** {@inheritDoc} */
    public function beginRegistration(
        Authenticatable $subject,
        SubjectReference $reference,
        array $excludedCredentialIds,
    ): PasskeyCeremonyOptions {
        $userHandle = $this->userHandle($reference);
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->relyingPartyName(), $this->relyingPartyId()),
            user: PublicKeyCredentialUserEntity::create(
                $this->subjectAttribute($subject, $this->usernameAttribute()) ?? $reference->identifier,
                $userHandle,
                $this->subjectAttribute($subject, $this->displayNameAttribute())
                    ?? $this->subjectAttribute($subject, $this->usernameAttribute())
                    ?? $reference->identifier,
            ),
            challenge: random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: $this->userVerification(),
                residentKey: $this->residentKey(),
            ),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $this->credentialDescriptors($excludedCredentialIds),
            timeout: $this->timeoutMilliseconds(),
        );
        $browserOptions = $this->normalizeOptions($options);

        return $this->ceremonyOptions(self::REGISTRATION, $browserOptions, [
            'subject_type' => $reference->type,
            'subject_id' => $reference->identifier,
        ]);
    }

    /** {@inheritDoc} */
    public function finishRegistration(
        SubjectReference $subject,
        array $state,
        array $response,
    ): PasskeyRegistration {
        $this->assertState($state, self::REGISTRATION);

        if (($state['subject_type'] ?? null) !== $subject->type
            || ($state['subject_id'] ?? null) !== $subject->identifier) {
            throw new InvalidArgumentException('The passkey registration subject does not match its ceremony.');
        }

        $options = $this->registrationOptions($state);
        $credential = $this->publicKeyCredential($response);

        if (! $credential->response instanceof AuthenticatorAttestationResponse) {
            throw new InvalidArgumentException('The passkey response is not a registration attestation.');
        }

        $record = $this->registrationValidator->check(
            $credential->response,
            $options,
            $this->relyingPartyId(),
        );

        return new PasskeyRegistration(
            credentialId: $this->encode($record->publicKeyCredentialId),
            publicKey: $this->encode($record->credentialPublicKey),
            userHandle: $this->encode($record->userHandle),
            signatureCounter: $record->counter,
            transports: array_values(array_unique($record->transports)),
            backupEligible: $record->backupEligible === true,
            backedUp: $record->backupStatus === true,
        );
    }

    /** {@inheritDoc} */
    public function beginAuthentication(
        ?SubjectReference $subject,
        array $allowedCredentialIds,
    ): PasskeyCeremonyOptions {
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->relyingPartyId(),
            allowCredentials: $this->credentialDescriptors($allowedCredentialIds),
            userVerification: $this->userVerification(),
            timeout: $this->timeoutMilliseconds(),
        );
        $browserOptions = $this->normalizeOptions($options);

        return $this->ceremonyOptions(self::AUTHENTICATION, $browserOptions, [
            'subject_scoped' => $subject instanceof SubjectReference,
        ]);
    }

    /** {@inheritDoc} */
    public function credentialId(array $response): string
    {
        return $this->encode($this->publicKeyCredential($response)->rawId);
    }

    /** {@inheritDoc} */
    public function finishAuthentication(
        array $state,
        array $response,
        PasskeyCredential $credential,
    ): PasskeyAssertion {
        $this->assertState($state, self::AUTHENTICATION);
        $subjectScoped = $state['subject_scoped'] ?? null;

        if (! is_bool($subjectScoped)) {
            throw new InvalidArgumentException('The passkey authentication scope is invalid.');
        }

        $options = $this->authenticationOptions($state);
        $publicKeyCredential = $this->publicKeyCredential($response);

        if (! $publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            throw new InvalidArgumentException('The passkey response is not an authentication assertion.');
        }

        $record = $this->authenticationValidator->check(
            $this->credentialRecord($credential),
            $publicKeyCredential->response,
            $options,
            $this->relyingPartyId(),
            $subjectScoped ? $this->decode($credential->userHandle) : null,
        );

        return new PasskeyAssertion(
            credentialId: $this->encode($record->publicKeyCredentialId),
            signatureCounter: $record->counter,
            backupEligible: $record->backupEligible === true,
            backedUp: $record->backupStatus === true,
            userVerified: $publicKeyCredential->response->authenticatorData->isUserVerified(),
        );
    }

    /**
     * Build a persisted ceremony and browser options from one normalized option set.
     *
     * @param  array<string, mixed>  $browserOptions
     * @param  array<string, mixed>  $state
     */
    private function ceremonyOptions(string $type, array $browserOptions, array $state): PasskeyCeremonyOptions
    {
        return new PasskeyCeremonyOptions(
            ceremonyId: $this->encode(random_bytes(32)),
            options: $browserOptions,
            state: [
                'version' => self::STATE_VERSION,
                'type' => $type,
                'options' => $browserOptions,
                ...$state,
            ],
            expiresAt: CarbonImmutable::now()->addSeconds($this->ceremonyTtlSeconds()),
        );
    }

    /**
     * Normalize standards objects into browser-safe and encrypted-at-rest arrays.
     *
     * @return array<string, mixed>
     */
    private function normalizeOptions(
        PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options,
    ): array {
        $normalized = $this->serializer->normalize($options, context: [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]);

        if (! is_array($normalized)) {
            throw new InvalidArgumentException('The WebAuthn options could not be normalized.');
        }

        /** @var array<string, mixed> $normalized */
        return $normalized;
    }

    /**
     * Restore persisted registration options.
     *
     * @param  array<string, mixed>  $state
     */
    private function registrationOptions(array $state): PublicKeyCredentialCreationOptions
    {
        $options = $this->serializer->denormalize(
            $this->stateOptions($state),
            PublicKeyCredentialCreationOptions::class,
        );

        return $options;
    }

    /**
     * Restore persisted authentication options.
     *
     * @param  array<string, mixed>  $state
     */
    private function authenticationOptions(array $state): PublicKeyCredentialRequestOptions
    {
        $options = $this->serializer->denormalize(
            $this->stateOptions($state),
            PublicKeyCredentialRequestOptions::class,
        );

        return $options;
    }

    /**
     * Parse one browser credential using the maintained WebAuthn serializer.
     *
     * @param  array<string, mixed>  $response
     */
    private function publicKeyCredential(array $response): PublicKeyCredential
    {
        $credential = $this->serializer->denormalize($response, PublicKeyCredential::class);

        if ($credential->type !== PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY) {
            throw new InvalidArgumentException('The browser passkey credential is invalid.');
        }

        return $credential;
    }

    /**
     * Restore one package-owned credential for assertion verification.
     */
    private function credentialRecord(PasskeyCredential $credential): CredentialRecord
    {
        return CredentialRecord::create(
            publicKeyCredentialId: $this->decode($credential->credentialId),
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            transports: [],
            attestationType: 'none',
            trustPath: EmptyTrustPath::create(),
            aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: $this->decode($credential->publicKey),
            userHandle: $this->decode($credential->userHandle),
            counter: $credential->signatureCounter,
            backupEligible: $credential->backupEligible,
            backupStatus: $credential->backedUp,
        );
    }

    /**
     * Convert stored credential identifiers into WebAuthn descriptors.
     *
     * @param  list<string>  $credentialIds
     * @return list<PublicKeyCredentialDescriptor>
     */
    private function credentialDescriptors(array $credentialIds): array
    {
        return array_map(
            fn (string $credentialId): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $this->decode($credentialId),
            ),
            $credentialIds,
        );
    }

    /**
     * Require a versioned, purpose-bound ceremony state.
     *
     * @param  array<string, mixed>  $state
     */
    private function assertState(array $state, string $type): void
    {
        if (($state['version'] ?? null) !== self::STATE_VERSION
            || ($state['type'] ?? null) !== $type
            || ! is_array($state['options'] ?? null)) {
            throw new InvalidArgumentException('The persisted passkey ceremony state is invalid.');
        }
    }

    /**
     * Read normalized options from validated ceremony state.
     *
     * @param  array<string, mixed>  $state
     * @return array<string, mixed>
     */
    private function stateOptions(array $state): array
    {
        $options = $state['options'] ?? null;

        if (! is_array($options)) {
            throw new InvalidArgumentException('The persisted WebAuthn options are invalid.');
        }

        /** @var array<string, mixed> $options */
        return $options;
    }

    /**
     * Derive a stable, opaque WebAuthn user handle from the host reference.
     */
    private function userHandle(SubjectReference $reference): string
    {
        return hash_hmac(
            'sha256',
            $reference->type."\0".$reference->identifier,
            $this->userHandleKey(),
            true,
        );
    }

    /**
     * Read a configured host-model attribute without requiring an Eloquent host.
     */
    private function subjectAttribute(Authenticatable $subject, string $attribute): ?string
    {
        if (! $subject instanceof Model) {
            return null;
        }

        $value = $subject->getAttribute($attribute);

        if ((! is_string($value) && ! is_int($value))
            || trim((string) $value) === ''
            || mb_strlen((string) $value) > 255) {
            return null;
        }

        return trim((string) $value);
    }

    /**
     * Resolve and validate the WebAuthn relying-party hostname.
     */
    private function relyingPartyId(): string
    {
        $relyingPartyId = $this->configuration->string('features.passkeys.settings.relying_party_id');

        if (mb_strlen($relyingPartyId) > 253
            || preg_match('/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/', $relyingPartyId) !== 1) {
            throw AuthException::invalidConfiguration(
                'Auth passkeys require a valid hostname-only relying-party ID.',
            );
        }

        return $relyingPartyId;
    }

    /**
     * Read the browser-facing relying-party name.
     */
    private function relyingPartyName(): string
    {
        $name = $this->configuration->string('features.passkeys.settings.relying_party_name', 'Laravel');

        if (mb_strlen($name) > 255) {
            throw AuthException::invalidConfiguration('Auth passkey relying-party names may contain at most 255 characters.');
        }

        return $name;
    }

    /**
     * Read exact HTTPS origins accepted by WebAuthn validation.
     *
     * @return list<string>
     */
    private function origins(): array
    {
        $origins = $this->configuration->get('features.passkeys.settings.origins', []);

        if (! is_array($origins) || $origins === [] || count($origins) > 32) {
            throw AuthException::invalidConfiguration('Auth passkeys require between 1 and 32 allowed origins.');
        }

        $relyingPartyId = $this->relyingPartyId();

        foreach ($origins as $origin) {
            $host = is_string($origin) ? parse_url($origin, PHP_URL_HOST) : null;
            $path = is_string($origin) ? parse_url($origin, PHP_URL_PATH) : null;

            if (! is_string($origin)
                || trim($origin) !== $origin
                || mb_strlen($origin) > 2_048
                || filter_var($origin, FILTER_VALIDATE_URL) === false
                || parse_url($origin, PHP_URL_SCHEME) !== 'https'
                || ! is_string($host)
                || ($host !== $relyingPartyId && ! str_ends_with($host, ".{$relyingPartyId}"))
                || (is_string($path) && $path !== '' && $path !== '/')
                || parse_url($origin, PHP_URL_USER) !== null
                || parse_url($origin, PHP_URL_PASS) !== null
                || parse_url($origin, PHP_URL_QUERY) !== null
                || parse_url($origin, PHP_URL_FRAGMENT) !== null) {
                throw AuthException::invalidConfiguration(
                    'Auth passkey origins must be HTTPS origins matching the relying-party ID.',
                );
            }
        }

        /** @var list<string> $origins */
        return array_values(array_unique($origins));
    }

    /**
     * Determine whether configured origins may match their subdomains.
     */
    private function allowSubdomains(): bool
    {
        return $this->configuration->boolean('features.passkeys.settings.allow_subdomains', false);
    }

    /**
     * Resolve browser user-verification policy.
     */
    private function userVerification(): string
    {
        return $this->configuration->boolean(
            'features.passkeys.settings.require_user_verification',
            true,
        ) ? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED
            : AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED;
    }

    /**
     * Resolve browser resident-credential policy.
     */
    private function residentKey(): string
    {
        $residentKey = $this->configuration->string('features.passkeys.settings.resident_key', 'required');

        if (! in_array($residentKey, [
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
        ], true)) {
            throw AuthException::invalidConfiguration(
                'Auth passkey resident-key policy must be required, preferred, or discouraged.',
            );
        }

        return $residentKey;
    }

    /**
     * Read the browser ceremony timeout.
     *
     * @return int<1000, 600000>
     */
    private function timeoutMilliseconds(): int
    {
        $timeout = $this->configuration->get('features.passkeys.settings.timeout_ms', 60_000);

        if (! is_int($timeout) || $timeout < 1_000 || $timeout > 600_000) {
            throw AuthException::invalidConfiguration(
                'Auth passkey browser timeout must be between 1,000 and 600,000 milliseconds.',
            );
        }

        return $timeout;
    }

    /**
     * Read the server-side ceremony lifetime.
     */
    private function ceremonyTtlSeconds(): int
    {
        $ttl = $this->configuration->integerBetween(
            'features.passkeys.settings.ceremony_ttl_seconds',
            300,
            60,
            900,
        );

        if ($ttl * 1_000 < $this->timeoutMilliseconds()) {
            throw AuthException::invalidConfiguration(
                'Auth passkey ceremony TTL must be at least as long as the browser timeout.',
            );
        }

        return $ttl;
    }

    /**
     * Read the registration username attribute.
     */
    private function usernameAttribute(): string
    {
        return $this->configuration->string('features.passkeys.settings.username_attribute', 'email');
    }

    /**
     * Read the registration display-name attribute.
     */
    private function displayNameAttribute(): string
    {
        return $this->configuration->string('features.passkeys.settings.display_name_attribute', 'name');
    }

    /**
     * Resolve at least 256 bits of stable user-handle key material.
     */
    private function userHandleKey(): string
    {
        $configured = $this->configuration->get('features.passkeys.settings.user_handle_key');
        $key = is_string($configured) && trim($configured) !== ''
            ? $configured
            : $this->applicationConfiguration->get('app.key');

        if (! is_string($key) || trim($key) === '') {
            throw AuthException::invalidConfiguration(
                'Auth passkeys require a user-handle key or Laravel application key.',
            );
        }

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);
            $key = is_string($decoded) ? $decoded : '';
        }

        if (strlen($key) < 32) {
            throw AuthException::invalidConfiguration(
                'Auth passkey user-handle key material must contain at least 32 bytes.',
            );
        }

        return $key;
    }

    /**
     * Encode binary WebAuthn material for encrypted string storage.
     */
    private function encode(string $value): string
    {
        return Base64UrlSafe::encodeUnpadded($value);
    }

    /**
     * Decode package-owned base64url WebAuthn material.
     */
    private function decode(string $value): string
    {
        return Base64UrlSafe::decodeNoPadding($value);
    }
}
