<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use CBOR\ByteStringObject;
use CBOR\Encoder;
use CBOR\MapObject;
use Cose\Algorithm\Signature\ECDSA\ECSignature;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;
use Webauthn\AuthenticatorData;
use Webauthn\U2FPublicKey;

/**
 * Emulates one WebAuthn ES256 authenticator with real attestations and signatures.
 */
final class TestWebauthnAuthenticator
{
    private const PRIVATE_KEY = <<<'PEM'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIExwigMuj7pGzk+XVIKVp72gYQc6AU//5HlUHb3X5HGRoAoGCCqGSM49
AwEHoUQDQgAE53mVK/HTD1mPae7VZ8uzETJC7ZLmAyWKa75YyZ9lNbHFl8oSKWJe
RYf/wGQSBmBTBSaU+rRuRbuVAx2zexNCzQ==
-----END EC PRIVATE KEY-----
PEM;

    private readonly OpenSSLAsymmetricKey $privateKey;

    private readonly string $credentialId;

    private readonly string $credentialPublicKey;

    /**
     * Create a deterministic virtual authenticator.
     */
    public function __construct()
    {
        $privateKey = openssl_pkey_get_private(self::PRIVATE_KEY);

        if (! $privateKey instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('The WebAuthn test private key could not be loaded.');
        }

        $details = openssl_pkey_get_details($privateKey);
        $ellipticCurve = is_array($details) ? ($details['ec'] ?? null) : null;
        $x = is_array($ellipticCurve) ? ($ellipticCurve['x'] ?? null) : null;
        $y = is_array($ellipticCurve) ? ($ellipticCurve['y'] ?? null) : null;

        if (! is_string($x) || ! is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
            throw new RuntimeException('The WebAuthn test public key is invalid.');
        }

        $this->privateKey = $privateKey;
        $this->credentialId = hash('sha256', 'nvl-auth-webauthn-test-credential', true);
        $this->credentialPublicKey = U2FPublicKey::convertToCoseKey("\x04".$x.$y);
    }

    /**
     * Build a standards-compliant fmt=none registration response.
     *
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function registrationResponse(
        array $options,
        string $origin = 'https://auth-package.test',
        bool $userVerified = true,
    ): array {
        $relyingParty = $options['rp'] ?? null;
        $relyingPartyId = is_array($relyingParty) ? ($relyingParty['id'] ?? null) : null;
        $challenge = $options['challenge'] ?? null;

        if (! is_string($relyingPartyId) || ! is_string($challenge)) {
            throw new RuntimeException('Registration options are missing RP or challenge data.');
        }

        $flags = AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_AT;
        $flags |= $userVerified ? AuthenticatorData::FLAG_UV : 0;
        $authenticatorData = hash('sha256', $relyingPartyId, true)
            .chr($flags)
            .pack('N', 0)
            .str_repeat("\0", 16)
            .pack('n', strlen($this->credentialId))
            .$this->credentialId
            .$this->credentialPublicKey;
        $attestationObject = (new Encoder)->encode([
            'fmt' => 'none',
            'attStmt' => MapObject::create(),
            'authData' => ByteStringObject::create($authenticatorData),
        ]);

        return [
            'id' => $this->credentialId(),
            'rawId' => $this->credentialId(),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->clientData('webauthn.create', $challenge, $origin),
                'attestationObject' => $this->encode($attestationObject),
                'transports' => ['internal'],
            ],
        ];
    }

    /**
     * Build a real ES256-signed authentication assertion.
     *
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function authenticationResponse(
        array $options,
        ?string $userHandle,
        int $signatureCounter = 1,
        string $origin = 'https://auth-package.test',
        bool $userVerified = true,
        bool $validSignature = true,
        ?string $challengeOverride = null,
        ?string $relyingPartyIdOverride = null,
    ): array {
        $relyingPartyId = $options['rpId'] ?? null;
        $challenge = $options['challenge'] ?? null;

        if (! is_string($relyingPartyId) || ! is_string($challenge) || $signatureCounter < 0) {
            throw new RuntimeException('Authentication options are missing RP, challenge, or counter data.');
        }

        $flags = AuthenticatorData::FLAG_UP;
        $flags |= $userVerified ? AuthenticatorData::FLAG_UV : 0;
        $authenticatorData = hash('sha256', $relyingPartyIdOverride ?? $relyingPartyId, true)
            .chr($flags)
            .pack('N', $signatureCounter);
        $clientData = $this->clientData(
            'webauthn.get',
            $challengeOverride ?? $challenge,
            $origin,
        );
        $clientDataJson = Base64UrlSafe::decodeNoPadding($clientData);
        $signedData = $authenticatorData.hash('sha256', $clientDataJson, true);
        $signed = openssl_sign($signedData, $derSignature, $this->privateKey, OPENSSL_ALGO_SHA256);

        if (! $signed || ! is_string($derSignature)) {
            throw new RuntimeException('The WebAuthn test assertion could not be signed.');
        }

        $signature = ECSignature::fromAsn1($derSignature, 64);

        if (! $validSignature) {
            $signature[0] = chr(ord($signature[0]) ^ 1);
        }

        return [
            'id' => $this->credentialId(),
            'rawId' => $this->credentialId(),
            'type' => 'public-key',
            'response' => [
                'authenticatorData' => $this->encode($authenticatorData),
                'clientDataJSON' => $clientData,
                'signature' => $this->encode($signature),
                'userHandle' => $userHandle,
            ],
        ];
    }

    /**
     * Return the canonical browser credential identifier.
     */
    public function credentialId(): string
    {
        return $this->encode($this->credentialId);
    }

    /**
     * Encode collected client data for one ceremony.
     */
    private function clientData(string $type, string $challenge, string $origin): string
    {
        $json = json_encode([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return $this->encode($json);
    }

    /**
     * Encode browser binary data as unpadded base64url.
     */
    private function encode(string $value): string
    {
        return Base64UrlSafe::encodeUnpadded($value);
    }
}
