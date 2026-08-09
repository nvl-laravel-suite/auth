<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Establishes a Laravel session after passwordless identity proof succeeds.
 */
final readonly class EstablishAuthenticatedSessionAction
{
    /**
     * Create the session establishment use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthSubjectResolver $subjects,
        private AuthManager $auth,
        private BrowserSession $session,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Resolve and log in a referenced host subject.
     */
    public function execute(SubjectReference $reference, bool $remember = false): Authenticatable
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $subject = $this->subjects->resolve($reference);

        if (! $subject instanceof Authenticatable) {
            throw new AuthException('subject_unavailable', 'The authentication subject is unavailable.', 404);
        }

        $guard = $this->auth->guard($this->configuration->string('guard', 'web'));

        if (! $guard instanceof StatefulGuard) {
            throw AuthException::invalidConfiguration('Passwordless authentication requires a stateful guard.');
        }

        $guard->login($subject, $remember);

        $this->session->regenerateIdentifier();

        $this->audits->record('authentication.passwordless', subject: $reference, actor: $subject);
        UserAuthenticated::dispatch($reference);

        return $subject;
    }
}
