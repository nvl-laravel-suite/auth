<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\RegistrationAdmission;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RegistrationMethod;
use Nvl\Auth\Enums\RegistrationMode;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Keeps native provisioning mode mandatory alongside replaceable host policy.
 *
 * @internal
 */
final readonly class ConfiguredRegistrationAdmission implements RegistrationAdmission
{
    public function __construct(private AuthConfiguration $configuration, private FeatureGate $features) {}

    public function mode(): RegistrationMode
    {
        return RegistrationMode::tryFrom($this->configuration->string('features.registration.settings.mode', 'closed'))
            ?? throw AuthException::invalidConfiguration('Registration mode must be closed, invitation_only or open.');
    }

    /** Only native invitation resolution may select the invited branch. */
    public function assertProvisioningAllowed(bool $invited = false, RegistrationMethod $method = RegistrationMethod::Password): void
    {
        $this->features->assertAllowed(AuthFeature::Registration, FeatureOperation::Issue);
        if ($method === RegistrationMethod::Password) {
            $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Issue);
        }
        $mode = $this->mode();
        if ($mode === RegistrationMode::Closed || (! $invited && $mode !== RegistrationMode::Open)) {
            throw new AuthException('registration_unavailable', 'Registration is unavailable.', 403);
        }
    }

    public function assertAllowed(RegistrationMethod $method, string $normalizedEmail, array $validatedExtensions): void
    {
        $this->assertProvisioningAllowed(invited: true, method: $method);
    }
}
