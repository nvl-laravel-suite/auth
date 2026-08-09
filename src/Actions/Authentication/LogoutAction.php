<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\UserLoggedOut;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Logs out through Laravel's configured stateful guard.
 */
final readonly class LogoutAction
{
    /**
     * Create the logout use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthManager $auth,
        private BrowserSession $session,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Log out and rotate the session CSRF state.
     */
    public function execute(): void
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Revoke);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $guard = $this->auth->guard($this->configuration->string('guard', 'web'));

        if (! $guard instanceof StatefulGuard) {
            throw AuthException::invalidConfiguration('The configured Auth logout guard must be stateful.');
        }

        $subject = $guard->user();
        $reference = $subject instanceof Authenticatable
            ? SubjectReference::fromAuthenticatable($subject)
            : null;
        $this->pipeline->run(
            'logout',
            new AuthPipelineContext('logout', subject: $reference),
            function () use ($guard, $reference, $subject): void {
                $guard->logout();

                $this->session->invalidate();
                $this->session->regenerateCsrfToken();

                $this->audits->record(
                    'authentication.logged_out',
                    subject: $reference,
                    actor: $subject instanceof Authenticatable ? $subject : null,
                );
                UserLoggedOut::dispatch($reference);
            },
        );
    }
}
