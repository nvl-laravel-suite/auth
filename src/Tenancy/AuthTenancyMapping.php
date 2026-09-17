<?php

declare(strict_types=1);

namespace Nvl\Auth\Tenancy;

use Illuminate\Support\Str;
use Nvl\Tenancy\Exceptions\TenantConfigurationInvalid;
use Nvl\Tenancy\ValueObjects\TenantAssignment;

/** Validates Auth's closed reviewed-adoption metadata schemas. */
final readonly class AuthTenancyMapping
{
    public function validate(TenantAssignment $assignment): void
    {
        if (! $this->uuid($assignment->recordId)) {
            throw new TenantConfigurationInvalid('Auth adoption record identifiers must be UUIDs.');
        }
        if ($assignment->resource === 'auth.roles'
            && ($assignment->metadata['source_id'] ?? null) === $assignment->recordId) {
            throw new TenantConfigurationInvalid('Auth role adoption requires distinct source and destination identifiers.');
        }

        match ($assignment->resource) {
            'auth.memberships' => $this->membership($assignment->metadata),
            'auth.roles' => $this->role($assignment->metadata),
            'auth.invitations' => $this->invitation($assignment->metadata),
            'auth.audits' => $this->audit($assignment->metadata),
            default => throw new TenantConfigurationInvalid('The Auth resource does not accept reviewed mappings.'),
        };
    }

    /** @param array<string, mixed> $metadata */
    private function membership(array $metadata): void
    {
        $this->keys($metadata, ['subject_type', 'subject_id', 'status', 'is_owner', 'role_ids', 'permission_ids']);
        if (! is_string($metadata['subject_type']) || trim($metadata['subject_type']) === '' || mb_strlen($metadata['subject_type']) > 160
            || ! is_string($metadata['subject_id']) || trim($metadata['subject_id']) === '' || mb_strlen($metadata['subject_id']) > 191
            || ! in_array($metadata['status'], ['active', 'suspended', 'revoked'], true)
            || ! is_bool($metadata['is_owner'])) {
            throw new TenantConfigurationInvalid('Auth membership mapping metadata is invalid.');
        }
        $this->identifiers($metadata['role_ids'], 100);
        $this->identifiers($metadata['permission_ids'], 250);
        if ($metadata['is_owner'] && $metadata['status'] !== 'active') {
            throw new TenantConfigurationInvalid('Auth membership owners must be active.');
        }
    }

    /** @param array<string, mixed> $metadata */
    private function role(array $metadata): void
    {
        $this->keys($metadata, ['source_id', 'parent_destination_id']);
        if (! is_string($metadata['source_id']) || ! $this->uuid($metadata['source_id'])
            || ($metadata['parent_destination_id'] !== null
                && (! is_string($metadata['parent_destination_id']) || ! $this->uuid($metadata['parent_destination_id'])))) {
            throw new TenantConfigurationInvalid('Auth role mapping metadata is invalid.');
        }
    }

    /** @param array<string, mixed> $metadata */
    private function invitation(array $metadata): void
    {
        $this->keys($metadata, ['role_ids', 'permission_ids']);
        $this->identifiers($metadata['role_ids'], 100);
        $this->identifiers($metadata['permission_ids'], 250);
    }

    /** @param array<string, mixed> $metadata */
    private function audit(array $metadata): void
    {
        $this->keys($metadata, ['evidence_reference']);
        if (! is_string($metadata['evidence_reference']) || trim($metadata['evidence_reference']) === ''
            || mb_strlen($metadata['evidence_reference']) > 191) {
            throw new TenantConfigurationInvalid('Auth audit mapping evidence is invalid.');
        }
    }

    /**
     * @param  array<string, mixed>  $metadata
     * @param  list<string>  $expected
     */
    private function keys(array $metadata, array $expected): void
    {
        $keys = array_keys($metadata);
        sort($keys);
        sort($expected);
        if ($keys !== $expected) {
            throw new TenantConfigurationInvalid('Auth adoption mapping metadata contains missing or unknown keys.');
        }
    }

    private function identifiers(mixed $value, int $maximum): void
    {
        if (! is_array($value) || ! array_is_list($value) || count($value) > $maximum
            || count(array_unique($value, SORT_REGULAR)) !== count($value)) {
            throw new TenantConfigurationInvalid('Auth adoption grant identifiers are invalid.');
        }
        foreach ($value as $identifier) {
            if (! is_string($identifier) || ! $this->uuid($identifier)) {
                throw new TenantConfigurationInvalid('Auth adoption grant identifiers must be UUIDs.');
            }
        }
    }

    /** Require the canonical lower-case textual UUID representation. */
    private function uuid(string $value): bool
    {
        return strlen($value) === 36 && strtolower($value) === $value && Str::isUuid($value);
    }
}
