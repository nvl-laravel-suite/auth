<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Supplies the static ability catalog from package configuration.
 */
final readonly class ConfiguredApiTokenAbilityProvider implements ApiTokenAbilityProvider
{
    /**
     * Create the configured ability provider.
     */
    public function __construct(private AuthConfiguration $configuration) {}

    /**
     * Return the configured ability catalog.
     */
    public function abilities(Authenticatable $subject): array
    {
        $configured = $this->configuration->get('features.api_tokens.settings.abilities', []);

        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration('API token abilities must be an array.');
        }

        $abilities = [];

        foreach ($configured as $ability) {
            if (! is_string($ability) || trim($ability) === '' || mb_strlen($ability) > 120) {
                throw AuthException::invalidConfiguration('API token abilities must be non-empty strings no longer than 120 characters.');
            }

            $abilities[] = $ability;
        }

        return array_values(array_unique($abilities));
    }
}
