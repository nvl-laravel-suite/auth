<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\Support\UniqueViolation;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;
use Throwable;

/**
 * Complete native AuthChallenges operations.
 *
 * @api
 */
final readonly class AuthChallenges
{
    use IssuesAuthenticationProofs;

    /** Create the magic-link and security-code challenge service. */
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private AuthSubjectResolver $subjects, private AuthenticationSessions $sessions, private AuthIdentityChallenges $records, private OpaqueTokenFactory $tokens, private SecretHasher $hasher, private AuthAuditRecorder $audits, private DomainEventDispatcher $domainEvents, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private AuthIdentifierResolver $identifiers, private PrincipalSecurity $security, private AuthCommittedAudit $committedAudits) {}

    /**
     * Issue a token or numeric-code challenge.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, mixed>  $metadata
     * @return array{challenge: Challenge, secret: string, fallbackCode: string|null}
     */
    public function issue(AuthFeature $feature, AuthMessageType $messageType, string $recipient, string $purpose, CarbonImmutable $expiresAt, bool $numeric = false, int $digits = 6, int $maxAttempts = 5, ?SubjectReference $subject = null, array $payload = [], array $metadata = [], ?string $locale = null, bool $withFallbackCode = false, int $fallbackDigits = 6): array
    {
        if (match ($messageType) {
            AuthMessageType::Invitation => AuthFeature::Invitations,
            AuthMessageType::MagicLink => AuthFeature::MagicLinks,
            AuthMessageType::SecurityCode => AuthFeature::SecurityCodes,
            AuthMessageType::PasswordReset => AuthFeature::Password,
            AuthMessageType::EmailVerification => AuthFeature::EmailVerification,
            default => null,
        } !== $feature) {
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }
        $this->features->assertAllowed($feature, FeatureOperation::Issue);
        if (trim($recipient) === '' || mb_strlen($recipient) > 320) {
            throw new InvalidArgumentException('Challenge recipients must contain between one and 320 characters.');
        }
        if (trim($purpose) === '' || mb_strlen($purpose) > 120) {
            throw new InvalidArgumentException('Challenge purposes must contain between one and 120 characters.');
        }
        if (! $expiresAt->isFuture()) {
            throw new InvalidArgumentException('Challenge expiry must be in the future.');
        }
        if ($maxAttempts < 1 || $maxAttempts > 100 || $numeric && ($digits < 4 || $digits > 10) || $withFallbackCode && ($numeric || $fallbackDigits < 4 || $fallbackDigits > 10)) {
            throw new InvalidArgumentException('Challenge attempt or numeric-code configuration is invalid.');
        }
        $normalizedRecipient = mb_strtolower(trim($recipient));
        $recipientHash = $this->hasher->hash('challenge-recipient', $normalizedRecipient);
        $activeKey = $this->hasher->hash('active-challenge', $messageType->value."\x00".$purpose."\x00".$recipientHash);
        $connection = (new Challenge)->getConnectionName();
        for ($draw = 1; ; $draw++) {
            $secret = $numeric ? str_pad((string) random_int(0, 10 ** $digits - 1), $digits, '0', STR_PAD_LEFT) : $this->tokens->make();
            $secretHash = $this->hasher->hash("challenge-{$messageType->value}-{$recipientHash}", $secret);
            $fallbackCode = $withFallbackCode ? str_pad((string) random_int(0, 10 ** $fallbackDigits - 1), $fallbackDigits, '0', STR_PAD_LEFT) : null;
            $secondarySecretHash = $fallbackCode === null ? null : $this->hasher->hash("challenge-{$messageType->value}-secondary-{$recipientHash}", $fallbackCode);
            try {
                return DB::connection($connection)->transaction(function () use ($activeKey, $expiresAt, $feature, $locale, $maxAttempts, $messageType, $metadata, $normalizedRecipient, $payload, $purpose, $recipientHash, $secret, $secretHash, $subject, $fallbackCode, $secondarySecretHash): array {
                    $this->records->query()->where('active_key', $activeKey)->update(['active_key' => null, 'revoked_at' => AuthInstantCast::forQuery((new Challenge)->getConnection(), CarbonImmutable::now('UTC'))]);
                    $challenge = $this->records->create(['type' => $messageType->value, 'purpose' => $purpose, 'subject_type' => $subject?->type, 'subject_id' => $subject?->identifier, 'recipient_hash' => $recipientHash, 'secret_hash' => $secretHash, 'secondary_secret_hash' => $secondarySecretHash, 'active_key' => $activeKey, 'payload' => $payload, 'max_attempts' => $maxAttempts, 'expires_at' => $expiresAt]);
                    $this->domainEvents->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: $feature, type: $messageType, recipient: $normalizedRecipient, payload: [...$payload, 'challenge_id' => $challenge->identifier(), 'secret' => $secret, 'code' => $fallbackCode, 'purpose' => $purpose], expiresAt: $expiresAt, locale: $locale, metadata: ['challenge_id' => $challenge->identifier(), ...$metadata], subject: $subject), $this->deliveryContext->capture(true)), $challenge->getConnection());
                    $this->audits->record("{$feature->value}.issued", subject: $subject, metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $purpose]);

                    return ['challenge' => $challenge, 'secret' => $secret, 'fallbackCode' => $fallbackCode];
                }, 3);
            } catch (UniqueConstraintViolationException $exception) {
                $column = $this->violatedUniqueColumn($exception);
                if ($column === null) {
                    throw $exception;
                }
                if ($column === 'active_key' || $draw === 3) {
                    throw new AuthException('challenge_issue_conflict', 'An authentication challenge is already being issued.', 409, previous: $exception);
                }
            }
        }
    }

    /**
     * Name the unique challenge column a rejected insert collided on.
     *
     * Code hashes are deterministic per recipient and type, so a retained challenge can already hold a newly drawn code.
     */
    private function violatedUniqueColumn(UniqueConstraintViolationException $exception): ?string
    {
        $challenge = new Challenge;
        $columns = UniqueViolation::columns($exception, $challenge->getConnection(), $challenge->getTable());

        return $columns !== null && count($columns) === 1 && in_array($columns[0], ['active_key', 'secret_hash', 'secondary_secret_hash'], true) ? $columns[0] : null;
    }

    /**
     * Consume a matching challenge or fail with a neutral error.
     */
    public function consume(AuthFeature $feature, AuthMessageType $messageType, string $recipient, string $purpose, string $secret): Challenge
    {
        if (match ($messageType) {
            AuthMessageType::Invitation => AuthFeature::Invitations,
            AuthMessageType::MagicLink => AuthFeature::MagicLinks,
            AuthMessageType::SecurityCode => AuthFeature::SecurityCodes,
            AuthMessageType::PasswordReset => AuthFeature::Password,
            AuthMessageType::EmailVerification => AuthFeature::EmailVerification,
            default => null,
        } !== $feature) {
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }
        $this->features->assertAllowed($feature, FeatureOperation::Use);
        $recipientHash = $this->hasher->hash('challenge-recipient', mb_strtolower(trim($recipient)));
        $secretHash = $this->hasher->hash("challenge-{$messageType->value}-{$recipientHash}", $secret);
        $secondarySecretHash = $this->hasher->hash("challenge-{$messageType->value}-secondary-{$recipientHash}", $secret);
        $connection = (new Challenge)->getConnectionName();
        $challenge = DB::connection($connection)->transaction(function () use ($messageType, $purpose, $recipientHash, $secretHash, $secondarySecretHash): ?Challenge {
            $this->records->query()->where('type', $messageType->value)->where('purpose', $purpose)->where('recipient_hash', $recipientHash)->whereNull('consumed_at')->whereNull('revoked_at')->where('expires_at', '<=', AuthInstantCast::forQuery((new Challenge)->getConnection(), CarbonImmutable::now('UTC')))->update(['active_key' => null]);
            /** @var Challenge|null $challenge */
            $challenge = $this->records->query()->where('type', $messageType->value)->where('purpose', $purpose)->where('recipient_hash', $recipientHash)->where(static fn ($query) => $query->where('secret_hash', $secretHash)->orWhere('secondary_secret_hash', $secondarySecretHash))->lockForUpdate()->first();
            if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
                /** @var Challenge|null $active */
                $active = $this->records->query()->where('type', $messageType->value)->where('purpose', $purpose)->where('recipient_hash', $recipientHash)->whereNull('consumed_at')->whereNull('revoked_at')->where('expires_at', '>', AuthInstantCast::forQuery((new Challenge)->getConnection(), CarbonImmutable::now('UTC')))->whereColumn('attempts', '<', 'max_attempts')->lockForUpdate()->first();
                if ($active instanceof Challenge) {
                    $attempts = min($active->attempts + 1, $active->max_attempts);
                    $this->records->save($active->forceFill(['attempts' => $attempts, 'active_key' => $attempts >= $active->max_attempts ? null : $active->active_key]));
                }

                return null;
            }
            $this->records->save($challenge->forceFill(['active_key' => null, 'consumed_at' => CarbonImmutable::now('UTC')]));
            if (is_string($challenge->subject_type) && is_string($challenge->subject_id)) {
                $subject = new SubjectReference($challenge->subject_type, $challenge->subject_id);
            } else {
                $subject = null;
            }
            $this->audits->record("{$messageType->value}.consumed", subject: $subject, metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $purpose]);

            return $challenge;
        }, 3);
        if (! $challenge instanceof Challenge) {
            $this->audits->record("{$messageType->value}.failed", outcome: 'failure', metadata: ['purpose' => $purpose]);
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }

        return $challenge;
    }

    /** Consume a primary token or secondary code without scanning active challenge rows. */
    public function consumeById(AuthFeature $feature, AuthMessageType $messageType, string $challengeId, string $purpose, string $secret): Challenge
    {
        if (match ($messageType) {
            AuthMessageType::Invitation => AuthFeature::Invitations,
            AuthMessageType::MagicLink => AuthFeature::MagicLinks,
            AuthMessageType::SecurityCode => AuthFeature::SecurityCodes,
            AuthMessageType::PasswordReset => AuthFeature::Password,
            AuthMessageType::EmailVerification => AuthFeature::EmailVerification,
            default => null,
        } !== $feature) {
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }
        $this->features->assertAllowed($feature, FeatureOperation::Use);
        $connection = (new Challenge)->getConnectionName();
        $challenge = DB::connection($connection)->transaction(function () use ($challengeId, $messageType, $purpose, $secret): ?Challenge {
            /** @var Challenge|null $challenge */
            $challenge = $this->records->query()->whereKey($challengeId)->where('type', $messageType->value)->where('purpose', $purpose)->lockForUpdate()->first();
            if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
                return null;
            }
            $primary = $this->hasher->hash("challenge-{$messageType->value}-{$challenge->recipient_hash}", $secret);
            $secondary = $this->hasher->hash("challenge-{$messageType->value}-secondary-{$challenge->recipient_hash}", $secret);
            if (! hash_equals($challenge->secret_hash, $primary) && (! is_string($challenge->secondary_secret_hash) || ! hash_equals($challenge->secondary_secret_hash, $secondary))) {
                $attempts = min($challenge->attempts + 1, $challenge->max_attempts);
                $this->records->save($challenge->forceFill(['attempts' => $attempts, 'active_key' => $attempts >= $challenge->max_attempts ? null : $challenge->active_key]));

                return null;
            }
            $this->records->save($challenge->forceFill(['active_key' => null, 'consumed_at' => CarbonImmutable::now('UTC')]));

            return $challenge;
        }, 3);
        if (! $challenge instanceof Challenge) {
            $this->audits->record("{$messageType->value}.failed", outcome: 'failure', metadata: ['challenge_id' => $challengeId, 'purpose' => $purpose]);
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }
        $subject = is_string($challenge->subject_type) && is_string($challenge->subject_id) ? new SubjectReference($challenge->subject_type, $challenge->subject_id) : null;
        $this->audits->record("{$messageType->value}.consumed", subject: $subject, metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $purpose]);

        return $challenge;
    }

    /**
     * Consume a matching magic link.
     *
     * @param  array<string, mixed>  $data
     */
    public function consumeMagicLink(array $data, string $purpose = 'login'): Challenge
    {
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Use);
        $data = $this->validateConsumeMagicLink($data);
        if ($data['challengeId'] !== null) {
            return $this->consumeById(AuthFeature::MagicLinks, AuthMessageType::MagicLink, $data['challengeId'], $purpose, $data['token']);
        }

        return $this->consume(AuthFeature::MagicLinks, AuthMessageType::MagicLink, (string) $data['recipient'], $purpose, $data['token']);
    }

    /**
     * Issue one magic link.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, mixed>  $data
     * @return array{challenge: Challenge, secret: string, fallbackCode: string|null}
     */
    public function requestMagicLink(array $data, ?SubjectReference $subject = null, array $payload = [], ?string $locale = null): array
    {
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Issue);
        $data = $this->validateRequestMagicLink($data);

        return $this->issue(feature: AuthFeature::MagicLinks, messageType: AuthMessageType::MagicLink, recipient: $data['recipient'], purpose: $data['purpose'] ?? 'login', expiresAt: CarbonImmutable::now('UTC')->addMinutes($this->configuration->integerBetween('features.magic_links.settings.ttl_minutes', 15, 1, 10080)), maxAttempts: $this->configuration->integerBetween('features.magic_links.settings.max_attempts', 5, 1, 100), subject: $subject, payload: $payload, locale: $locale, withFallbackCode: true, fallbackDigits: $this->configuration->integerBetween('features.magic_links.settings.fallback_code_digits', 6, 4, 10));
    }

    /**
     * Resolve an eligible subject and issue a bound login link when one exists.
     *
     * @param  array<string, mixed>  $data
     * @return array{challenge: Challenge, secret: string, fallbackCode: string|null}|null
     */
    public function requestMagicLinkAuthentication(array $data, AuthenticationRequestContext $context, ?string $locale = null): ?array
    {
        $data = $this->validateRequestMagicLink($data);

        $issued = $this->issueNativeEmail($data['recipient'], AuthenticationMethod::EmailLink, $context, $locale);
        $reference = $issued === null ? null : new SubjectReference((string) $issued['challenge']->subject_type, (string) $issued['challenge']->subject_id);
        $metadata = $issued === null ? ['matched' => false] : ['matched' => true, 'challenge_id' => $issued['challenge']->identifier()];
        $this->committedAudits->withRecorder($this->audits)->record((new Challenge)->getConnection(), 'magic_links.requested', subject: $reference, metadata: $metadata);

        return $issued;
    }

    /**
     * Issue one security code.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, mixed>  $data
     * @return array{challenge: Challenge, secret: string, fallbackCode: string|null}
     */
    public function requestSecurityCode(array $data, ?SubjectReference $subject = null, array $payload = [], ?string $locale = null): array
    {
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Issue);
        $data = $this->validateRequestSecurityCode($data);

        return $this->issue(feature: AuthFeature::SecurityCodes, messageType: AuthMessageType::SecurityCode, recipient: $data['recipient'], purpose: $data['purpose'], expiresAt: CarbonImmutable::now('UTC')->addMinutes($this->configuration->integerBetween('features.security_codes.settings.ttl_minutes', 10, 1, 10080)), numeric: true, digits: $this->configuration->integerBetween('features.security_codes.settings.digits', 6, 4, 10), maxAttempts: $this->configuration->integerBetween('features.security_codes.settings.max_attempts', 5, 1, 100), subject: $subject, payload: $payload, locale: $locale);
    }

    /** Issue a passwordless-login email code bound to the requesting browser context.
     * @param  array<string, mixed>  $data
     * @return array{challenge: Challenge, secret: string, fallbackCode: string|null}|null
     */
    public function requestSecurityCodeAuthentication(array $data, AuthenticationRequestContext $context, ?string $locale = null): ?array
    {
        $data = $this->validateRequestSecurityCode($data);
        if ($data['purpose'] !== AuthenticationPurpose::PasswordlessLogin->value) {
            throw new AuthException('security_code_authentication_purpose_invalid', 'Security-code authentication requires the passwordless login purpose.', 422);
        }

        return $this->issueNativeEmail($data['recipient'], AuthenticationMethod::EmailCode, $context, $locale);
    }

    /**
     * Consume a matching security code.
     *
     * @param  array<string, mixed>  $data
     */
    public function verifySecurityCode(array $data): Challenge
    {
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Use);
        $data = $this->validateVerifySecurityCode($data);

        return $this->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, $data['recipient'], $data['purpose'], $data['code']);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{recipient: string|null, token: string, challengeId: string|null}
     */
    private function validateConsumeMagicLink(array $data): array
    {
        if (array_diff(array_keys($data), ['recipient', 'token', 'challengeId']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! (array_key_exists('recipient', $data) && $data['recipient'] === null || is_string($data['recipient'] ?? null))) {
            throw new InvalidArgumentException('Invalid Auth input [recipient].');
        }
        if (! is_string($data['token'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [token].');
        }
        if (! array_key_exists('challengeId', $data)) {
            $data['challengeId'] = null;
        }
        if (! ($data['challengeId'] === null || is_string($data['challengeId']))) {
            throw new InvalidArgumentException('Invalid Auth input [challengeId].');
        }
        Validator::make($data, ['token' => ['required', 'string', 'max:255'], 'recipient' => ['nullable', 'required_without:challengeId', 'email:rfc', 'max:320'], 'challengeId' => ['nullable', 'required_without:recipient', 'uuid']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{recipient: string, purpose: string|null}
     */
    private function validateRequestMagicLink(array $data): array
    {
        if (array_diff(array_keys($data), ['recipient', 'purpose']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['recipient'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [recipient].');
        }
        if (! array_key_exists('purpose', $data)) {
            $data['purpose'] = 'login';
        }
        if (! ($data['purpose'] === null || is_string($data['purpose']))) {
            throw new InvalidArgumentException('Invalid Auth input [purpose].');
        }
        Validator::make($data, ['recipient' => ['required', 'string', 'max:255'], 'purpose' => ['nullable', 'sometimes', 'string', 'max:120']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{recipient: string, purpose: string}
     */
    private function validateRequestSecurityCode(array $data): array
    {
        if (array_diff(array_keys($data), ['recipient', 'purpose']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['recipient'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [recipient].');
        }
        if (! is_string($data['purpose'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [purpose].');
        }
        Validator::make($data, ['recipient' => ['required', 'string', 'max:255'], 'purpose' => ['required', 'string', 'max:255']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{recipient: string, purpose: string, code: string}
     */
    private function validateVerifySecurityCode(array $data): array
    {
        if (array_diff(array_keys($data), ['recipient', 'purpose', 'code']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['recipient'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [recipient].');
        }
        if (! is_string($data['purpose'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [purpose].');
        }
        if (! is_string($data['code'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [code].');
        }
        Validator::make($data, ['recipient' => ['required', 'string', 'max:255'], 'purpose' => ['required', 'string', 'max:255'], 'code' => ['required', 'string', 'max:128']])->validate();

        return $data;
    }

    /** @param array<string, mixed> $data */
    public function consumeMagicLinkAuthentication(#[\SensitiveParameter] array $data, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        $data = $this->validateConsumeMagicLink($data);

        return $this->consumeNativeEmail(AuthenticationMethod::EmailLink, $context, $data['token'], $data['recipient'], $data['challengeId']);
    }

    /** @param array<string, mixed> $data */
    public function proveSecurityCodeAuthentication(#[\SensitiveParameter] array $data, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        $data = $this->validateVerifySecurityCode($data);
        if ($data['purpose'] !== AuthenticationPurpose::PasswordlessLogin->value) {
            throw new AuthException('security_code_authentication_purpose_invalid', 'Security-code authentication requires the passwordless login purpose.', 422);
        }

        return $this->consumeNativeEmail(AuthenticationMethod::EmailCode, $context, $data['code'], $data['recipient']);
    }

    /** Verify native delivery and complete the consumer-supplied browser transport.
     * @param  array<string, mixed>  $data
     */
    public function verifySecurityCodeAuthentication(#[\SensitiveParameter] array $data, StatefulGuard $guard, Session $session, AuthenticationRequestContext $context): Authenticatable
    {
        $this->sessions->assertCanTransition();
        $proof = $this->proveSecurityCodeAuthentication($data, $context);

        return $this->sessions->establishFromProof($proof->reveal(), $guard, $session, $context);
    }

    /** @return array{challenge: Challenge, secret: string, fallbackCode: string|null}|null */
    private function issueNativeEmail(string $recipient, AuthenticationMethod $method, AuthenticationRequestContext $context, ?string $locale): ?array
    {
        $context->assertBound(AuthenticationDestination::Session);
        $feature = $method === AuthenticationMethod::EmailLink ? AuthFeature::MagicLinks : AuthFeature::SecurityCodes;
        $message = $method === AuthenticationMethod::EmailLink ? AuthMessageType::MagicLink : AuthMessageType::SecurityCode;
        $this->features->assertAllowed($feature, FeatureOperation::Issue);
        $subject = $this->identifiers->resolve($this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email')), $recipient);
        if ($subject === null) {
            return null;
        }
        if (! $subject instanceof Model || $subject->getConnection() !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Native delivery and principal require one source.');
        }

        return $subject->getConnection()->transaction(function () use ($subject, $recipient, $method, $context, $locale, $feature, $message): array {
            $revision = $this->security->lock($subject)->revision;
            $this->security->lockChallenges($subject);
            $reference = SubjectReference::fromAuthenticatable($subject);
            $recipient = mb_strtolower(trim($recipient));
            $recipientHash = $this->hasher->hash('native-email-recipient', $recipient);
            $type = 'native_'.$method->value;
            $digits = $this->configuration->integerBetween('features.'.$feature->value.'.settings.'.($method === AuthenticationMethod::EmailLink ? 'fallback_code_digits' : 'digits'), 6, 4, 10);
            $ttlMinutes = $this->configuration->integerBetween('features.'.$feature->value.'.settings.ttl_minutes', $method === AuthenticationMethod::EmailLink ? 15 : 10, 1, 10080);
            $maximumAttempts = $this->configuration->integerBetween('features.'.$feature->value.'.settings.max_attempts', 5, 1, 100);
            $secret = $method === AuthenticationMethod::EmailLink ? bin2hex(random_bytes(32)) : str_pad((string) random_int(0, 10 ** $digits - 1), $digits, '0', STR_PAD_LEFT);
            $fallback = $method === AuthenticationMethod::EmailLink ? str_pad((string) random_int(0, 10 ** $digits - 1), $digits, '0', STR_PAD_LEFT) : null;
            $expiresAt = CarbonImmutable::now('UTC')->addMinutes($ttlMinutes);
            $active = $this->nativeEmailKey($type, $recipientHash, $context);
            $secretNamespace = (string) Str::uuid();
            $this->records->query()->where('active_key', $active)->update(['active_key' => null, 'revoked_at' => AuthInstantCast::forQuery((new Challenge)->getConnection(), now())]);
            $challenge = $this->records->create(['type' => $type, 'purpose' => $method->purpose()->value, 'subject_type' => $reference->type, 'subject_id' => $reference->identifier,
                'recipient_hash' => $recipientHash, 'secret_hash' => $this->hasher->hash($type.':'.$secretNamespace, $secret), 'secondary_secret_hash' => $fallback === null ? null : $this->hasher->hash($type.':'.$secretNamespace, $fallback),
                'active_key' => $active, 'payload' => ['revision' => $revision, 'context' => $context->facts(), 'secretNamespace' => $secretNamespace], 'max_attempts' => $maximumAttempts, 'expires_at' => $expiresAt]);
            $this->domainEvents->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: $feature, type: $message, recipient: $recipient,
                payload: ['challenge_id' => $challenge->identifier(), 'secret' => $secret, 'code' => $fallback, 'purpose' => $method->purpose()->value], expiresAt: $expiresAt, locale: $locale,
                metadata: ['challenge_id' => $challenge->identifier()], subject: $reference), $this->deliveryContext->capture(true)), $challenge->getConnection());
            $this->committedAudits->withRecorder($this->audits)->record($challenge->getConnection(), $feature->value.'.issued', subject: $reference, metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $method->purpose()->value]);

            return ['challenge' => $challenge, 'secret' => $secret, 'fallbackCode' => $fallback];
        });
    }

    private function consumeNativeEmail(AuthenticationMethod $method, AuthenticationRequestContext $context, #[\SensitiveParameter] string $secret, ?string $recipient, ?string $challengeId = null): IssuedAuthenticationProof
    {
        $context->assertBound(AuthenticationDestination::Session);
        $this->features->assertAllowed($method === AuthenticationMethod::EmailLink ? AuthFeature::MagicLinks : AuthFeature::SecurityCodes, FeatureOperation::Use);
        $type = 'native_'.$method->value;
        $query = $this->records->query()->where('type', $type)->whereNull('consumed_at')->whereNull('revoked_at');
        if ($challengeId !== null) {
            $query->whereKey($challengeId);
        } else {
            $recipientHash = $this->hasher->hash('native-email-recipient', mb_strtolower(trim((string) $recipient)));
            $query->where('active_key', $this->nativeEmailKey($type, $recipientHash, $context));
        }
        $snapshot = $query->latest()->first();
        if (! $snapshot instanceof Challenge || ! is_string($snapshot->subject_type) || ! is_string($snapshot->subject_id)) {
            $this->recordNativeEmailFailure($method, $challengeId);
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }
        $reference = new SubjectReference($snapshot->subject_type, $snapshot->subject_id);
        $subject = $this->subjects->resolve($reference);
        if (! $subject instanceof Model || SubjectReference::fromAuthenticatable($subject) != $reference || $subject->getConnection() !== $snapshot->getConnection()) {
            $this->recordNativeEmailFailure($method, $challengeId);
            throw new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
        }
        $result = $subject->getConnection()->transaction(function () use ($subject, $snapshot, $context, $method, $type, $secret): IssuedAuthenticationProof|Throwable {
            $revision = $this->security->lock($subject)->revision;
            $this->security->lockChallenges($subject);
            $challenge = $this->records->query()->whereKey($snapshot->identifier())->where('type', $type)->lockForUpdate()->first();
            if (! $challenge instanceof Challenge || ! $challenge->isUsable() || $challenge->payload !== $snapshot->payload || ($challenge->payload['revision'] ?? null) !== $revision || ($challenge->payload['context'] ?? null) !== $context->facts() || ! is_string($challenge->payload['secretNamespace'] ?? null)) {
                return new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
            }
            if (! hash_equals($challenge->secret_hash, $this->hasher->hash($type.':'.$challenge->payload['secretNamespace'], $secret)) && ! hash_equals((string) $challenge->secondary_secret_hash, $this->hasher->hash($type.':'.$challenge->payload['secretNamespace'], $secret))) {
                $challenge->attempts++;
                $this->records->save($challenge);

                return new AuthException('challenge_invalid', 'The authentication challenge is invalid or expired.', 422);
            }
            $challenge->consumed_at = CarbonImmutable::now('UTC');
            $challenge->active_key = null;
            $this->records->save($challenge);

            $proof = $this->issueNativeProof($subject, $method, AuthenticationDestination::Session, $context, $revision);
            $message = $method === AuthenticationMethod::EmailLink ? AuthMessageType::MagicLink : AuthMessageType::SecurityCode;
            $this->committedAudits->withRecorder($this->audits)->record($challenge->getConnection(), $message->value.'.consumed', subject: SubjectReference::fromAuthenticatable($subject), metadata: ['challenge_id' => $challenge->identifier(), 'purpose' => $method->purpose()->value]);

            return $proof;
        });
        if ($result instanceof Throwable) {
            $this->recordNativeEmailFailure($method, $challengeId);
            throw $result;
        }

        return $result;
    }

    private function recordNativeEmailFailure(AuthenticationMethod $method, ?string $challengeId): void
    {
        $message = $method === AuthenticationMethod::EmailLink ? AuthMessageType::MagicLink : AuthMessageType::SecurityCode;
        $metadata = ['purpose' => $method->purpose()->value];
        if ($challengeId !== null) {
            $metadata['challenge_id'] = $challengeId;
        }
        $this->committedAudits->withRecorder($this->audits)->record((new Challenge)->getConnection(), $message->value.'.failed', outcome: 'failure', metadata: $metadata);
    }

    private function nativeEmailKey(string $type, string $recipientHash, AuthenticationRequestContext $context): string
    {
        return $this->hasher->hash('native-email-active', json_encode([$type, $recipientHash, $context->guardName, $context->sessionBinding], JSON_THROW_ON_ERROR));
    }
}
