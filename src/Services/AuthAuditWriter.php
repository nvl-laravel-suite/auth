<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use JsonException;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Events\AuthAuditRecorded;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Enums\TenantContextMode;

/** Persists an Auth audit against an already-captured ownership context. */
final readonly class AuthAuditWriter
{
    public function __construct(
        private AuthConfiguration $configuration,
        private AuthAuditContextProvider $request,
    ) {}

    /** @param array<string, mixed> $metadata */
    public function write(
        AuthEventContext $context,
        string $action,
        string $outcome,
        ?SubjectReference $subject,
        ?Authenticatable $actor,
        ?string $clientId,
        array $metadata,
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
            $encoded = json_encode($metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new AuthException('invalid_audit_metadata', 'Auth audit metadata must be JSON-serializable.', 500, previous: $exception);
        }
        if (strlen($encoded) > 32_768) {
            throw new AuthException('invalid_audit_metadata', 'Auth audit metadata exceeds 32 KiB.', 500);
        }
        $actorReference = $actor instanceof Authenticatable
            ? SubjectReference::fromAuthenticatable($actor)
            : null;
        $audit = AuthAudit::query()->create([
            ...$this->ownership($context),
            'action' => $action,
            'outcome' => $outcome,
            'subject_type' => $subject?->type,
            'subject_id' => $subject?->identifier,
            'actor_type' => $actorReference?->type,
            'actor_id' => $actorReference?->identifier,
            'client_id' => $clientId,
            'ip_address' => $this->configuration->boolean('features.audit.settings.capture_ip', true)
                ? $this->bounded($this->request->ipAddress(), 64) : null,
            'user_agent' => $this->configuration->boolean('features.audit.settings.capture_user_agent', true)
                ? $this->bounded($this->request->userAgent(), 1_024) : null,
            'request_id' => $this->bounded($this->request->requestId(), 128),
            'metadata' => $metadata,
        ]);
        AuthAuditRecorded::dispatch($audit->identifier());

        return $audit;
    }

    /** @return array{tenant_id?: string|null, ownership_key?: string} */
    private function ownership(AuthEventContext $context): array
    {
        if (config('tenancy.enabled') !== true) {
            return [];
        }

        return match ($context->mode) {
            TenantContextMode::Tenant => [
                'tenant_id' => $context->tenantId?->value,
                'ownership_key' => 'tenant:'.$context->tenantId?->value,
            ],
            TenantContextMode::Platform => ['tenant_id' => null, 'ownership_key' => 'platform'],
            default => throw new AuthException('tenant_audit_context_required', 'Tenant audit ownership is required.', 500),
        };
    }

    private function bounded(?string $value, int $maximumBytes): ?string
    {
        return $value === null ? null : substr($value, 0, $maximumBytes);
    }
}
