<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\SocialIdentities;

use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SocialProviderConfiguration;
use Throwable;

/**
 * Starts one allowlisted, stateful social authorization flow.
 */
final readonly class StartSocialAuthorizationAction
{
    /**
     * Create the social authorization start use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SocialProviderConfiguration $configuration,
        private SocialIdentityProvider $provider,
    ) {}

    /**
     * Return the provider redirect URL.
     */
    public function execute(string $provider): string
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Issue);
        $configuration = $this->configuration->provider($provider);

        try {
            $url = $this->provider->redirectUrl(
                $provider,
                $configuration['callback_url'],
                $configuration['scopes'],
                $configuration['parameters'],
            );
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException(
                'social_provider_unavailable',
                'The social authorization provider is unavailable.',
                502,
                previous: $exception,
            );
        }

        $parts = parse_url($url);

        if (mb_strlen($url) > 8_192
            || filter_var($url, FILTER_VALIDATE_URL) === false
            || ! is_array($parts)
            || ! in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || ! is_string($parts['host'] ?? null)
            || isset($parts['user'])
            || isset($parts['pass'])
            || preg_match('/[\x00-\x1F\x7F]/', $url) === 1) {
            throw AuthException::invalidConfiguration('The social identity provider returned an invalid redirect URL.');
        }

        return $url;
    }
}
