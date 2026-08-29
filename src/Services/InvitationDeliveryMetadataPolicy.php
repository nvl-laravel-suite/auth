<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Data\Display\AuthSubjectReferenceData;
use Nvl\Auth\Data\Display\InvitationDeliveryData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Projects explicitly allowed, bounded invitation data for delivery listeners.
 */
final readonly class InvitationDeliveryMetadataPolicy
{
    private const FORBIDDEN_KEY_PARTS = [
        'token',
        'secret',
        'password',
        'hash',
        'signature',
        'payload',
        'credential',
        'active_key',
    ];

    /**
     * Create the invitation delivery projection policy.
     */
    public function __construct(private AuthConfiguration $configuration) {}

    /**
     * Determine whether the configured metadata allowlist is safe.
     */
    public function configurationIsValid(): bool
    {
        return $this->deliveryMetadataKeys() !== null;
    }

    /**
     * Build current invitation context from an already loaded model.
     */
    public function deliveryData(Invitation $invitation): InvitationDeliveryData
    {
        $keys = $this->deliveryMetadataKeys();

        if ($keys === null) {
            throw AuthException::invalidConfiguration(
                'Invitation delivery metadata keys must be a bounded safe allowlist.',
            );
        }

        $metadata = $invitation->metadata ?? [];
        $deliveryMetadata = [];

        foreach ($keys as $key) {
            if (! array_key_exists($key, $metadata)) {
                continue;
            }

            $value = $metadata[$key];

            if (! is_scalar($value) && $value !== null) {
                throw new AuthException(
                    'invitation_delivery_metadata_invalid',
                    'Invitation delivery metadata values must be scalar or null.',
                    422,
                );
            }

            if (is_string($value) && mb_strlen($value) > 255) {
                throw new AuthException(
                    'invitation_delivery_metadata_invalid',
                    'Invitation delivery metadata strings must not exceed 255 characters.',
                    422,
                );
            }

            $deliveryMetadata[$key] = $value;
        }

        $inviter = $invitation->inviter_type !== null && $invitation->inviter_id !== null
            ? AuthSubjectReferenceData::fromReference(new SubjectReference(
                $invitation->inviter_type,
                $invitation->inviter_id,
            ))
            : null;

        return new InvitationDeliveryData(
            id: $invitation->identifier(),
            type: $invitation->type,
            purpose: $invitation->purpose,
            recipient: $invitation->recipient,
            inviter: $inviter,
            roles: $this->grantList($invitation->roles, 100, 'roles'),
            permissions: $this->grantList($invitation->permissions, 250, 'permissions'),
            metadata: $deliveryMetadata,
            expiresAt: $invitation->expires_at,
            resendCount: $invitation->resend_count,
        );
    }

    /**
     * Read a valid metadata allowlist or return null when configuration is unsafe.
     *
     * @return list<string>|null
     */
    private function deliveryMetadataKeys(): ?array
    {
        $keys = $this->configuration->get(
            'features.invitations.settings.delivery_metadata_keys',
            [],
        );

        if (! is_array($keys) || ! array_is_list($keys) || count($keys) > 50) {
            return null;
        }

        foreach ($keys as $key) {
            if (! is_string($key)
                || mb_strlen($key) > 120
                || preg_match('/\A[a-z][a-z0-9]*(?:_[a-z0-9]+)*\z/', $key) !== 1
                || $this->hasForbiddenPart($key)) {
                return null;
            }
        }

        return array_values(array_unique($keys));
    }

    /**
     * Determine whether a metadata key suggests protected material.
     */
    private function hasForbiddenPart(string $key): bool
    {
        foreach (self::FORBIDDEN_KEY_PARTS as $part) {
            if (str_contains($key, $part)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Revalidate stored grants at the queue projection boundary.
     *
     * @return list<string>
     */
    private function grantList(mixed $grants, int $maximum, string $field): array
    {
        if ($grants === null) {
            return [];
        }

        if (! is_array($grants) || ! array_is_list($grants) || count($grants) > $maximum) {
            throw AuthException::invalidConfiguration(
                "Invitation delivery {$field} must be a distinct bounded list.",
            );
        }

        $seen = [];

        foreach ($grants as $grant) {
            if (! is_string($grant)
                || trim($grant) === ''
                || mb_strlen($grant) > 255
                || isset($seen[$grant])) {
                throw AuthException::invalidConfiguration(
                    "Invitation delivery {$field} must be a distinct bounded list.",
                );
            }

            $seen[$grant] = true;
        }

        return $grants;
    }
}
