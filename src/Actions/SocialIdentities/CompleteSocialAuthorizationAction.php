<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\SocialIdentities;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SocialProviderConfiguration;
use Throwable;

/**
 * Orchestrates provider acquisition, subject resolution, and canonical identity linking.
 */
final readonly class CompleteSocialAuthorizationAction
{
    /**
     * Create the social callback use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SocialProviderConfiguration $configuration,
        private SocialIdentityProvider $provider,
        private SocialSubjectResolver $subjects,
        private LinkSocialIdentityAction $links,
    ) {}

    /**
     * Acquire provider claims and link them to a supplied or resolved host subject.
     */
    public function execute(
        string $provider,
        ?Authenticatable $subject = null,
    ): SocialIdentity {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Use);
        $configuration = $this->configuration->provider($provider);

        try {
            $identity = $this->provider->user($provider, $configuration['callback_url']);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException(
                'social_authorization_failed',
                'The social authorization could not be completed.',
                422,
                previous: $exception,
            );
        }

        $resolvedSubject = $subject ?? $this->subjects->resolve($identity);

        return $this->links->execute($resolvedSubject, $identity);
    }
}
