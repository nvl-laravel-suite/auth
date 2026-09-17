<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\SocialIdentities;

use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SocialProviderConfiguration;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Tenancy\ValueObjects\TenantId;
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
        private AuthOperationBoundary $operations,
        private TenantAuthenticationIntents $intents,
        private TenantAuthenticationSession $session,
    ) {}

    /**
     * Return the provider redirect URL.
     */
    public function execute(
        string $provider,
        ?TenantId $tenant = null,
        ?string $returnPath = null,
    ): string {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Issue);
        $this->operations->central(AuthIdentityOperation::SocialIdentity);
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

        if (config('tenancy.enabled') === true && $tenant instanceof TenantId) {
            parse_str((string) ($parts['query'] ?? ''), $query);
            $state = $query['state'] ?? null;
            if (! is_string($state) || trim($state) === '') {
                throw AuthException::invalidConfiguration('Tenant social login requires Socialite state.');
            }
            $flow = "social:{$provider}:{$state}";
            $issued = $this->intents->issue(
                $tenant,
                TenantAuthenticationPurpose::SocialLogin,
                $this->session->authenticationFlowBinding($flow),
                provider: $provider,
                returnPath: $returnPath,
            );
            $this->session->storeAuthenticationIntent($flow, $issued->nonce);
        }

        return $url;
    }
}
