<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Writes only closed, global identity audit families with platform ownership.
 *
 * @internal
 */
final readonly class CentralIdentityAuditRecorder
{
    public function __construct(private AuthAuditWriter $writer) {}

    /** @param array<string, mixed> $metadata
     * @param  array{}|array{actor_type: string, actor_id: string, effective_subject_type: string, effective_subject_id: string, impersonation_id: string}|null  $attribution
     */
    public function record(
        AuthIdentityOperation $operation,
        string $action,
        string $outcome = 'success',
        ?SubjectReference $subject = null,
        ?Authenticatable $actor = null,
        array $metadata = [],
        ?array $attribution = null,
    ): ?AuthAudit {
        if (! $this->allowed($operation, $action)) {
            throw AuthException::invalidConfiguration('The central identity audit action is not allowlisted for its operation.');
        }

        return $this->writer->write(
            AuthEventContext::centralIdentity(),
            $action,
            $outcome,
            $subject,
            $actor,
            null,
            $metadata,
            $attribution,
        );
    }

    private function allowed(AuthIdentityOperation $operation, string $action): bool
    {
        $prefixes = match ($operation) {
            AuthIdentityOperation::Login, AuthIdentityOperation::Logout => ['authentication.', 'session.', 'client.'],
            AuthIdentityOperation::Recovery, AuthIdentityOperation::Password => ['password.', 'magic_link.', 'magic_links.', 'security_code.', 'security_codes.'],
            AuthIdentityOperation::VerifyEmail => ['email_verification.', 'email_change.'],
            AuthIdentityOperation::Impersonation => ['impersonation.'],
            AuthIdentityOperation::Registration => ['registration.'],
            AuthIdentityOperation::Profile => ['profile.', 'account.'],
            AuthIdentityOperation::Mfa => ['totp.', 'passkey.', 'recovery_code.'],
            AuthIdentityOperation::SocialIdentity => ['social_identity.'],
            AuthIdentityOperation::MembershipDiscovery => ['membership.discovery'],
        };

        return array_any($prefixes, static fn (string $prefix): bool => str_starts_with($action, $prefix));
    }
}
