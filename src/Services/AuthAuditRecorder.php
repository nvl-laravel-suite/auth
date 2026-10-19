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
use Nvl\Support\Tenancy\Contracts\TenantContext;
use Nvl\Support\Tenancy\Enums\TenantContextMode;

/**
 * Records package audit facts when the audit feature is enabled.
 */
final readonly class AuthAuditRecorder implements AuthAuditRecorderContract
{
    /**
     * Create the audit recorder.
     */
    public function __construct(
        private TenantContext $tenantContext,
        private AuthAuditWriter $writer,
        private CentralIdentityAuditRecorder $central,
        private OwnershipContext $ownership,
        private OwnershipQueueContext $queue,
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
        if (config('nvl-auth.ownership.scoped') === true
            && in_array($this->ownership->snapshot()->mode, [OwnershipContextMode::Owner, OwnershipContextMode::Central], true)) {
            return $this->writer->write(new AuthEventContext(TenantContextMode::Disabled), $action, $outcome, $subject, $actor, $clientId, $metadata);
        }

        return ($this->prepare($action, $outcome, $subject, $actor, $clientId, $metadata))();
    }

    /**
     * Capture ownership before a deferred native audit is registered.
     *
     * @internal
     *
     * @param  array<string, mixed>  $metadata
     * @return Closure(): ?AuthAudit
     */
    public function prepare(
        string $action,
        string $outcome = 'success',
        ?SubjectReference $subject = null,
        ?Authenticatable $actor = null,
        ?string $clientId = null,
        array $metadata = [],
    ): Closure {
        if (config('nvl-auth.ownership.scoped') === true) {
            $snapshot = $this->ownership->snapshot();
            if ($snapshot->mode === OwnershipContextMode::Unresolved) {
                $operation = $this->centralOperation($action);
                if (! $operation instanceof AuthIdentityOperation || $clientId !== null) {
                    throw new AuthException('owner_audit_context_required', 'Owner audit admission is required.', 500);
                }

                return fn (): ?AuthAudit => $this->central->record($operation, $action, $outcome, $subject, $actor, $metadata);
            }
            $envelope = OwnershipJobEnvelope::capture($this->ownership);

            return fn (): ?AuthAudit => $this->queue->run($envelope, fn (): ?AuthAudit => $this->writer->write(
                new AuthEventContext(TenantContextMode::Disabled), $action, $outcome, $subject, $actor, $clientId, $metadata,
            ));
        }
        $snapshot = $this->tenantContext->snapshot();

        return function () use ($snapshot, $action, $outcome, $subject, $actor, $clientId, $metadata): ?AuthAudit {
            if (config('nvl-tenancy.enabled') !== true
                || in_array($snapshot->mode, [TenantContextMode::Tenant, TenantContextMode::Platform], true)) {
                return $this->writer->write(
                    new AuthEventContext($snapshot->mode, $snapshot->tenantId),
                    $action,
                    $outcome,
                    $subject,
                    $actor,
                    $clientId,
                    $metadata,
                );
            }
            $operation = $this->centralOperation($action);
            if (! $operation instanceof AuthIdentityOperation || $clientId !== null) {
                throw new AuthException('tenant_audit_context_required', 'Tenant audit ownership is required.', 500);
            }

            return $this->central->record($operation, $action, $outcome, $subject, $actor, $metadata);
        };
    }

    private function centralOperation(string $action): ?AuthIdentityOperation
    {
        foreach ([
            AuthIdentityOperation::Login->value => ['authentication.', 'session.', 'client.'],
            AuthIdentityOperation::Recovery->value => ['magic_link.', 'magic_links.', 'security_code.', 'security_codes.'],
            AuthIdentityOperation::Password->value => ['password.'],
            AuthIdentityOperation::VerifyEmail->value => ['email_verification.'],
            AuthIdentityOperation::Profile->value => ['profile.', 'account.'],
            AuthIdentityOperation::Mfa->value => ['totp.', 'passkey.', 'recovery_code.'],
            AuthIdentityOperation::SocialIdentity->value => ['social_identity.'],
        ] as $operation => $prefixes) {
            if (array_any($prefixes, static fn (string $prefix): bool => str_starts_with($action, $prefix))) {
                return AuthIdentityOperation::from($operation);
            }
        }

        return null;
    }
}
