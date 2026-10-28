<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;

/**
 * Safe discovery and local readiness for explicitly configured connections.
 *
 * @api
 */
final readonly class SocialProviderRegistry
{
    public function __construct(private AuthConfiguration $configuration, private SocialProviderConfiguration $providers, private SocialIdentityProviderFactory $factory) {}

    /** @return array<string, array{enabled: bool, label: string, supportsReauthentication: bool}> */
    public function providers(): array
    {
        $configured = $this->configuration->get('features.social_identities.settings.providers', []);
        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration('Social connections must be an array.');
        }
        $result = [];
        foreach ($configured as $name => $settings) {
            if (! is_string($name) || preg_match('/\A[a-z0-9][a-z0-9_.-]{0,79}\z/', $name) !== 1 || ! is_array($settings)) {
                throw AuthException::invalidConfiguration('Invalid social connection.');
            }
            $label = $settings['label'] ?? $name;
            $enabled = $settings['enabled'] ?? true;
            $reauthentication = $settings['supports_reauthentication'] ?? false;
            if (! is_string($label) || trim($label) === '' || strlen($label) > 120 || ! is_bool($enabled) || ! is_bool($reauthentication)) {
                throw AuthException::invalidConfiguration('Invalid social discovery settings.');
            }
            $result[$name] = ['enabled' => $enabled && $this->configuration->enabled() && $this->configuration->featureEnabled(AuthFeature::Authentication) && $this->configuration->featureEnabled(AuthFeature::SocialIdentities), 'label' => $label, 'supportsReauthentication' => $reauthentication];
        }

        return $result;
    }

    /** Resolve a fresh local adapter without acquiring claims or making HTTP calls. */
    public function assertAvailable(string $provider): void
    {
        if (! ($this->providers()[$provider]['enabled'] ?? false)) {
            throw new AuthException('social_provider_unavailable', 'The social provider is unavailable.', 404);
        }
        $this->providers->provider($provider);
        $this->factory->make($provider);
        $settings = $this->configuration->get("features.social_identities.settings.providers.{$provider}", []);
        $realm = is_array($settings) ? ($settings['realm'] ?? null) : null;
        if ($realm !== null) {
            if (! is_string($realm) || trim($realm) === '' || strlen($realm) > 255) {
                throw AuthException::invalidConfiguration('Social realm must be a fixed bounded identifier.');
            }
            foreach (SocialIdentity::query()->where('provider', $provider)->cursor() as $identity) {
                if (($identity->profile['connection_realm'] ?? null) !== $realm) {
                    throw AuthException::invalidConfiguration('Retained social identities require an explicit realm adoption before changing a connection.');
                }
            }
        }
    }
}
