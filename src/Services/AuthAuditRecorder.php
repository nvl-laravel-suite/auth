<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthAuditRecorder as AuthAuditRecorderContract;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Contracts\OwnershipQueueContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;

/**
 * Records package audit facts when the audit feature is enabled.
 *
 * @internal
 */
final readonly class AuthAuditRecorder implements AuthAuditRecorderContract
{
    /**
     * Create the audit recorder.
     */
    public function __construct(private AuthAuditWriter $writer, private CentralIdentityAuditRecorder $central, private OwnershipContext $ownership, private OwnershipQueueContext $queue, private AuthExecutionContext $execution) {}

    /**
     * Record one Auth audit when the audit feature is enabled.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function record(string $action, string $outcome = 'success', ?SubjectReference $subject = null, ?Authenticatable $actor = null, ?string $clientId = null, array $metadata = []): ?AuthAudit
    {
        if (config('nvl-auth.ownership.scoped') === true && str_starts_with($action, 'impersonation.')) {
            return $this->central->record(AuthIdentityOperation::Impersonation, $action, $outcome, $subject, $actor, $metadata);
        }
        if (config('nvl-auth.ownership.scoped') === true && in_array($this->ownership->snapshot()->mode, [OwnershipContextMode::Owner, OwnershipContextMode::Central], true)) {
            return $this->writer->write(new AuthEventContext(OwnershipContextMode::Disabled), $action, $outcome, $subject, $actor, $clientId, $metadata);
        }

        return $this->prepare($action, $outcome, $subject, $actor, $clientId, $metadata)();
    }

    /**
     * Capture ownership before a deferred native audit is registered.
     *
     * @internal
     *
     * @param  array<string, mixed>  $metadata
     * @return Closure(): ?AuthAudit
     */
    public function prepare(string $action, string $outcome = 'success', ?SubjectReference $subject = null, ?Authenticatable $actor = null, ?string $clientId = null, array $metadata = []): Closure
    {
        if (array_intersect(array_keys($metadata), ['effective_subject_type', 'effective_subject_id', 'impersonation_id']) !== []) {
            throw new AuthException('reserved_audit_metadata', 'Impersonation attribution is reserved for the verified native context.', 422);
        }
        $attribution = $this->execution->facts() ?? [];
        if (config('nvl-auth.ownership.scoped') === true && str_starts_with($action, 'impersonation.')) {
            return fn (): ?AuthAudit => $this->central->record(AuthIdentityOperation::Impersonation, $action, $outcome, $subject, $actor, $metadata, $attribution);
        }
        if (config('nvl-auth.ownership.scoped') === true) {
            $snapshot = $this->ownership->snapshot();
            if ($snapshot->mode === OwnershipContextMode::Unresolved) {
                $operation = $this->centralOperation($action);
                if (! $operation instanceof AuthIdentityOperation || $clientId !== null) {
                    throw new AuthException('owner_audit_context_required', 'Owner audit admission is required.', 500);
                }

                return fn (): ?AuthAudit => $this->central->record($operation, $action, $outcome, $subject, $actor, $metadata, $attribution);
            }
            $envelope = OwnershipJobEnvelope::capture($this->ownership);

            return fn (): ?AuthAudit => $this->queue->run($envelope, fn (): ?AuthAudit => $this->writer->write(new AuthEventContext(OwnershipContextMode::Disabled), $action, $outcome, $subject, $actor, $clientId, $metadata, $attribution));
        }

        return fn (): ?AuthAudit => $this->writer->write(new AuthEventContext(OwnershipContextMode::Disabled), $action, $outcome, $subject, $actor, $clientId, $metadata, $attribution);
    }

    /** Map an audit action prefix to the central identity operation it belongs to. */
    private function centralOperation(string $action): ?AuthIdentityOperation
    {
        foreach ([AuthIdentityOperation::Impersonation->value => ['impersonation.'], AuthIdentityOperation::Registration->value => ['registration.'], AuthIdentityOperation::Login->value => ['authentication.', 'session.', 'client.'], AuthIdentityOperation::Recovery->value => ['magic_link.', 'magic_links.', 'security_code.', 'security_codes.'], AuthIdentityOperation::Password->value => ['password.'], AuthIdentityOperation::VerifyEmail->value => ['email_verification.', 'email_change.'], AuthIdentityOperation::Profile->value => ['profile.', 'account.'], AuthIdentityOperation::Mfa->value => ['totp.', 'passkey.', 'recovery_code.'], AuthIdentityOperation::SocialIdentity->value => ['social_identity.']] as $operation => $prefixes) {
            if (array_any($prefixes, static fn (string $prefix): bool => str_starts_with($action, $prefix))) {
                return AuthIdentityOperation::from($operation);
            }
        }

        return null;
    }
}
