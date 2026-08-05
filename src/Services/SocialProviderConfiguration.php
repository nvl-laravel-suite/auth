<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Exceptions\AuthException;

/**
 * Validates the allowlisted social provider configuration.
 */
final readonly class SocialProviderConfiguration
{
    /**
     * Create the provider configuration reader.
     */
    public function __construct(private AuthConfiguration $configuration) {}

    /**
     * Return normalized configuration for one provider.
     *
     * @return array{callback_url: string|null, scopes: list<string>, parameters: array<string, scalar>}
     */
    public function provider(string $provider): array
    {
        $configured = $this->configuration->get(
            "features.social_identities.settings.providers.{$provider}",
        );

        if (! is_array($configured)) {
            throw new AuthException('social_provider_unavailable', 'The social provider is unavailable.', 404);
        }

        $callbackUrl = $configured['callback_url'] ?? null;
        $scopes = $configured['scopes'] ?? [];
        $parameters = $configured['parameters'] ?? [];

        if (($callbackUrl !== null && (! is_string($callbackUrl) || filter_var($callbackUrl, FILTER_VALIDATE_URL) === false))
            || ! is_array($scopes)
            || ! is_array($parameters)) {
            throw AuthException::invalidConfiguration(
                "Social provider [{$provider}] has invalid callback, scopes, or parameters.",
            );
        }

        $normalizedScopes = [];

        foreach ($scopes as $scope) {
            if (! is_string($scope) || trim($scope) === '') {
                throw AuthException::invalidConfiguration("Social provider [{$provider}] scopes must be strings.");
            }

            $normalizedScopes[] = $scope;
        }

        $normalizedParameters = [];

        foreach ($parameters as $key => $value) {
            if (! is_string($key) || (! is_string($value) && ! is_int($value) && ! is_float($value) && ! is_bool($value))) {
                throw AuthException::invalidConfiguration("Social provider [{$provider}] parameters must be scalar.");
            }

            $normalizedParameters[$key] = $value;
        }

        return [
            'callback_url' => $callbackUrl,
            'scopes' => $normalizedScopes,
            'parameters' => $normalizedParameters,
        ];
    }
}
