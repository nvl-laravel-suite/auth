<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\DeleteOwnAccountData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Confirms and contains credentials before self-service principal deletion.
 */
final readonly class DeleteOwnAccountAction
{
    /** Create the self-service deletion use case. */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private UserLocator $users,
        private AccountConfirmation $confirmation,
        private AuthManager $auth,
        private BrowserSession $session,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Delete the authenticated package principal and revoke every active credential. */
    public function execute(Authenticatable $subject, DeleteOwnAccountData $data): bool
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $user = $this->users->authenticated($subject);
        $this->confirmation->assertConfirmed($user, $data->currentPassword);
        $guard = $this->auth->guard($this->configuration->string('guard', 'web'));

        if (! $guard instanceof StatefulGuard) {
            throw AuthException::invalidConfiguration('Self-service deletion requires a stateful guard.');
        }

        $deleted = DB::connection($user->getConnectionName())->transaction(function () use ($user): bool {
            $reference = SubjectReference::fromAuthenticatable($user);
            $tokens = $user->tokens();

            if (Schema::connection($user->getConnectionName())->hasTable($tokens->getModel()->getTable())) {
                $tokens->delete();
            }
            $deleted = (bool) $user->delete();
            $this->audits->record('user.self_deleted', subject: $reference, actor: $user);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'self_deleted');

            return $deleted;
        }, 3);

        $guard->logout();
        $this->session->invalidate();
        $this->session->regenerateCsrfToken();

        return $deleted;
    }
}
