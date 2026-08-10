<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;

/**
 * Maps package registration fields to the configured principal schema.
 */
final readonly class PackageInvitationRegistrationMapper implements InvitationRegistrationMapper
{
    /** Create the package registration mapper. */
    public function __construct(
        private AuthConfiguration $configuration,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** {@inheritDoc} */
    public function map(Invitation $invitation, array $validated): array
    {
        $name = $validated['name'] ?? null;
        $password = $validated['password'] ?? null;

        if (! is_string($name) || trim($name) === '' || mb_strlen($name) > 160
            || ! is_string($password) || mb_strlen($password) < 8) {
            throw new AuthException(
                'invitation_registration_invalid',
                'Invitation registration requires a valid name and password.',
                422,
            );
        }

        return $this->attributes->map([
            PrincipalAttribute::Name->value => trim($name),
            PrincipalAttribute::Email->value => mb_strtolower(trim($invitation->recipient)),
            PrincipalAttribute::Password->value => $password,
            PrincipalAttribute::Active->value => true,
            PrincipalAttribute::Locale->value => $this->boundedString($validated['locale'] ?? null, 12)
                ?? $this->configuration->string('features.principal_management.settings.default_locale', 'en'),
            PrincipalAttribute::Timezone->value => $this->boundedString($validated['timezone'] ?? null, 64)
                ?? $this->configuration->string('features.principal_management.settings.default_timezone', 'UTC'),
            PrincipalAttribute::Profile->value => is_array($validated['extensions'] ?? null)
                ? $validated['extensions']
                : [],
        ]);
    }

    /** Return one bounded optional string. */
    private function boundedString(mixed $value, int $maximum): ?string
    {
        return is_string($value) && trim($value) !== '' && mb_strlen($value) <= $maximum
            ? trim($value)
            : null;
    }
}
