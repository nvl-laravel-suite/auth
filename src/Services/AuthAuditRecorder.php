<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthAuditRecorder as AuthAuditRecorderContract;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Enums\TenantContextMode;

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
        $snapshot = $this->tenantContext->snapshot();
        if (config('tenancy.enabled') !== true
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
