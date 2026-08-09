<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use JsonException;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder as AuthAuditRecorderContract;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Events\AuthAuditRecorded;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Records package audit facts when the audit feature is enabled.
 */
final readonly class AuthAuditRecorder implements AuthAuditRecorderContract
{
    /**
     * Create the audit recorder.
     */
    public function __construct(
        private AuthConfiguration $configuration,
        private AuthAuditContextProvider $context,
    ) {}

    /**
     * Record one Auth audit when the audit feature is enabled.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function record(
        string $action,
        string $outcome = 'success',
        ?SubjectReference $subject = null,
        ?Authenticatable $actor = null,
        ?string $clientId = null,
        array $metadata = [],
    ): ?AuthAudit {
        if (! $this->configuration->featureEnabled(AuthFeature::Audit)) {
            return null;
        }

        $action = trim($action);
        $outcome = trim($outcome);

        if ($action === '' || mb_strlen($action) > 120 || $outcome === '' || mb_strlen($outcome) > 40) {
            throw AuthException::invalidConfiguration('Auth audit action or outcome exceeds its schema boundary.');
        }

        try {
            $encodedMetadata = json_encode($metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new AuthException(
                'invalid_audit_metadata',
                'Auth audit metadata must be JSON-serializable.',
                500,
                previous: $exception,
            );
        }

        if (strlen($encodedMetadata) > 32_768) {
            throw new AuthException('invalid_audit_metadata', 'Auth audit metadata exceeds 32 KiB.', 500);
        }

        $actorReference = $actor instanceof Authenticatable
            ? SubjectReference::fromAuthenticatable($actor)
            : null;
        $audit = AuthAudit::query()->create([
            'action' => $action,
            'outcome' => $outcome,
            'subject_type' => $subject?->type,
            'subject_id' => $subject?->identifier,
            'actor_type' => $actorReference?->type,
            'actor_id' => $actorReference?->identifier,
            'client_id' => $clientId,
            'ip_address' => $this->configuration->boolean('features.audit.settings.capture_ip', true)
                ? $this->bounded($this->context->ipAddress(), 64)
                : null,
            'user_agent' => $this->configuration->boolean('features.audit.settings.capture_user_agent', true)
                ? $this->bounded($this->context->userAgent(), 1_024)
                : null,
            'request_id' => $this->bounded($this->context->requestId(), 128),
            'metadata' => $metadata,
        ]);

        AuthAuditRecorded::dispatch($audit->identifier());

        return $audit;
    }

    /**
     * Bound untrusted request context without allowing audit capture to fail Auth.
     */
    private function bounded(?string $value, int $maximumBytes): ?string
    {
        if ($value === null) {
            return null;
        }

        return substr($value, 0, $maximumBytes);
    }
}
