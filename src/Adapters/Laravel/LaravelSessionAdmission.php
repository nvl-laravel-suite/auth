<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Auth\AuthManager;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\AuthenticationSessions;

/** Host middleware calls this after session/authentication and before application authorization. @api */
final readonly class LaravelSessionAdmission
{
    public function __construct(private AuthBrowserSessions $sessions, private AuthenticationSessions $transitions, private AuthManager $auth) {}

    public function admit(StatefulGuard $guard, Session $session, string $guardName): void
    {
        $this->transitions->assertCanTransition();
        try {
            if ($this->auth->guard($guardName) !== $guard) {
                throw new AuthException('browser_session_invalid', 'The selected guard does not match.', 401);
            }
            $subject = $guard->user();
            $binding = $session->get(AuthBrowserSessions::bindingKey($guardName));
            if ($subject === null || ! is_string($binding)) {
                throw new AuthException('browser_session_invalid', 'The browser session is unavailable.', 401);
            }
            $this->sessions->admit($subject, $guardName, $binding);
        } catch (\Throwable $exception) {
            try {
                $guard->logout();
            } finally {
                if ($guard instanceof SessionGuard) {
                    $guard->forgetUser();
                } try {
                    $session->invalidate();
                } finally {
                    $session->regenerateToken();
                }
            }
            throw $exception;
        }
    }
}
